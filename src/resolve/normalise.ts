// Normaliser: the deterministic name understanding the other agents lean on.
//
//   parseSoftware(raw)            messy inventory string -> vendor hint, product hint, version, product type, tokens
//   kevProductType(pair)          the same type lexicon applied to a KEV (vendor, product) pair
//   familyOf(pair)                one key per product family across KEV's own spellings ("Windows" = "Windows ")
//   topCandidates(parsed, pairs)  the top-K KEV pairs: alias-expanded token score + Jaro-Winkler + vendor + type
//   normaliserVote(row, ...)      the deterministic "third vote" (and the offline resolver in sample mode)
//   familiesOf / pairsMentioning  every family a KEV combo names, and the KEV spellings to fetch for one family
//   matchedKevPart(parsed, pair)  the product of a combo a row matched, with its family and type
//   cloudCueSource(parsed)        whether a cloud_service type comes from the main text or only from a bracketed note
//
// Pure functions, no I/O, no clock, no randomness: the same input always gives the same output.
// The alias and type tables are general product knowledge (abbreviations, vendor product lines), never
// whole-row answers. KEV pairs are returned exactly as KEV spells them; familyOf groups the variants.
import type {
  Candidate, InventoryRow, JurorVote, KevPair, ParsedSoftware, ProductType,
} from "../contracts.ts";

// ---------- thresholds (exported so the critic, the eval and the docs can cite them) ----------
export const NORMALISER_THRESHOLDS = {
  /** The best type-compatible candidate must score at least this to get the normaliser's vote. */
  match_min: 0.7,
  /** ...and beat the best compatible candidate of another family by at least this much. */
  margin_min: 0.08,
  /** Below this, nothing in KEV resembles the row: a confident "no match". */
  no_match_max: 0.45,
  /** Name resemblance at which a type-blocked candidate counts as a look-alike. */
  lookalike_name_min: 0.45,
  /** At most this many spellings of one family in a top-K list, so other families keep their slots. */
  family_cap: 4,
  /**
   * A null vote at or above this confidence means "no KEV product matches" (no_match); below it means
   * "unsure" (abstain). Same convention as the v0 placeholder's CONFIDENT_NONE.
   */
  no_match_confidence_min: 0.6,
} as const;

const T = NORMALISER_THRESHOLDS;
const CONF_NO_MATCH = 0.8;   // nothing resembles the row
const CONF_LOOKALIKE = 0.7;  // a same-name product of another type (Exchange Online vs Exchange Server)
const CONF_ABSTAIN = 0.3;    // close call or middling score
const CONF_EMPTY = 0.2;      // nothing to go on (no product words)

// ---------- text basics ----------

/** Unicode-safe clean-up: drop marks and zero-width characters, NFKC (U+202F, U+00A0 -> space), collapse, trim. */
export function cleanText(s: string): string {
  return String(s ?? "")
    .replace(/[®™©]/g, " ")
    .replace(/[​-‍⁠﻿]/g, "")
    .normalize("NFKC")
    .replace(/\s+/g, " ")
    .trim();
}

const lowerClean = (s: string): string => cleanText(s).toLowerCase();

/** "for Windows", "for Android": the platform a product runs on, not what the product is. */
const PLATFORM_RE = /\bfor (?:microsoft )?(?:windows|mac|macos|os x|linux|android|ios|ipados|iphone|ipad|chromebooks?)\b/g;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9+]+/g, "-").replace(/^-+|-+$/g, "");
}

// ---------- versions ----------

// In priority order; each captures the version in group 1.
const VERSION_RES: RegExp[] = [
  // year + update level: "2019 CU12", "2016 SP2", "2008 R2", "2019 U3"
  /(?<![\w.])((?:19|20)\d{2}\s?(?:cu|sp|u|r|update\s?)\s?\d{1,3})(?![\w.])/i,
  // dotted, with Cisco "(4)", "-48.47" / "-h3", "R2"/"k" and "build 48.47" / "U3" / "SP1" suffixes
  /(?<![\w.])v?(\d+(?:\.\d+)+(?:\(\d+\)[a-z]*\d*)?(?:-[a-z]{0,2}\d+(?:\.\d+)*)?(?:[a-z]{1,3}\d*)?(?:\s?build\s?\d+(?:\.\d+)*)?(?:\s(?:u|update|sp|cu|r|p|patch|hf|hotfix)\s?\d+)?)(?![\w.])/i,
  // Java "8u381", Windows "22H2", "8 Update 381"
  /(?<![\w.])(\d+u\d+|\d{2}h\d|\d+\supdate\s\d+)(?![\w.])/i,
  // "v8"
  /(?<![\w.])v(\d+)(?![\w.])/i,
  // a bare year: "Office 2016", "SQL Server 2019"
  /(?<![\w.-])((?:19|20)\d{2})(?![\w.-])/,
];

function tidyVersion(v: string): string {
  return v
    .replace(/\s+/g, " ")
    .replace(/^(\d+(?:\.\d+)+)\s?build\s?(\d+(?:\.\d+)*)$/i, "$1-$2") // Citrix "13.1 Build 48.47" -> "13.1-48.47"
    .trim();
}

/**
 * The first version-like substring (by pattern priority), and the text without it.
 * Bare integers ("Struts 2", "Windows 10") and hardware models ("60F") are not versions.
 */
export function extractVersion(text: string): { version: string | null; rest: string } {
  const s = String(text ?? "");
  for (const re of VERSION_RES) {
    const m = re.exec(s);
    if (m && m[1]) return { version: tidyVersion(m[1]), rest: `${s.slice(0, m.index)} ${s.slice(m.index + m[0].length)}` };
  }
  return { version: null, rest: s };
}

const NOISE_RES: RegExp[] = [
  /\b(?:x64|x86|x86_64|amd64|arm64|aarch64|win64|64-?bit|32-?bit)\b/gi,
  /\bbuild\s*[:#]?\s*\d+(?:\.\d+)*\b/gi,
  /\b(?:rev|revision)\s*[:#]?\s*\d+\b/gi,
  /\b(?:inc|ltd|llc|corp|corporation|gmbh)\b\.?/gi,
];
const stripNoise = (s: string): string => NOISE_RES.reduce((acc, re) => acc.replace(re, " "), s);

// ---------- vendors ----------

/** Vendor names written in the string. Values are KEV's spellings. */
const VENDOR_WORDS: [RegExp, string][] = [
  [/\b(?:microsoft|msft|ms)\b/i, "Microsoft"],
  [/\bapache\b/i, "Apache"],
  [/\bcitrix\b/i, "Citrix"],
  [/\bfortinet\b/i, "Fortinet"],
  [/\bcisco\b/i, "Cisco"],
  [/\bgoogle\b/i, "Google"],
  [/\badobe\b/i, "Adobe"],
  [/\b(?:ivanti|pulse ?secure)\b/i, "Ivanti"],
  [/\bpalo ?alto(?: networks)?\b/i, "Palo Alto Networks"],
  [/\bvmware\b/i, "VMware"],
  [/\boracle\b/i, "Oracle"],
  [/\bmozilla\b/i, "Mozilla"],
  [/\bapple\b/i, "Apple"],
  [/\batlassian\b/i, "Atlassian"],
  [/\bsolarwinds\b/i, "SolarWinds"],
  [/\bsonicwall\b/i, "SonicWall"],
  [/\bjuniper(?: networks)?\b/i, "Juniper"],
  [/\bf5\b/i, "F5"],
  [/\bzyxel\b/i, "Zyxel"],
  [/\b(?:zoho|manageengine)\b/i, "Zoho"],
  [/\bprogress\b/i, "Progress"],
  [/\brarlab\b/i, "RARLAB"],
  [/\bveeam\b/i, "Veeam"],
  [/\bsap\b/i, "SAP"],
];

/** Product names that imply their vendor (FortiGate -> Fortinet, httpd -> Apache, PAN-OS -> Palo Alto Networks). */
const PRODUCT_VENDOR: [RegExp, string][] = [
  [/\b(?:exchange|sharepoint|outlook|windows|win ?(?:7|8|10|11)|office|excel|powerpoint|wordpad|iis|internet explorer|skype|sql server|mssql|visual studio|defender|active directory|m365|o365|azure|hyper-v|win32k|smbv[13]|sccm|configuration manager)\b/i, "Microsoft"],
  [/\b(?:log4j\S*|httpd|apache2|tomcat|struts\S*|activemq|solr|ofbiz|airflow|shiro|kylin|superset|couchdb|rocketmq|flink|apisix)\b/i, "Apache"],
  [/\b(?:netscaler|xenapp|xendesktop|xenmobile|sharefile|storefront)\b/i, "Citrix"],
  [/\bforti[a-z]*/i, "Fortinet"],
  [/\b(?:pan-?os|globalprotect|panorama)\b/i, "Palo Alto Networks"],
  [/\b(?:connect ?secure|policy ?secure|epmm|mobileiron)\b/i, "Ivanti"],
  [/\b(?:vcenter|vcsa|esxi?|vsphere|workspace one|vrealize)\b/i, "VMware"],
  [/\b(?:anyconnect|asa|ios[- ]?x[er]|nx-?os|firepower|webex)\b/i, "Cisco"],
  [/\b(?:chrome|chromium)\b/i, "Google"],
  [/\b(?:acrobat|flash player|coldfusion|magento)\b/i, "Adobe"],
  [/\b(?:firefox|thunderbird)\b/i, "Mozilla"],
  [/\b(?:macos|ipados|safari|webkit)\b/i, "Apple"],
  [/\b(?:confluence|jira|bitbucket)\b/i, "Atlassian"],
  [/\bwinrar\b/i, "RARLAB"],
  [/\b7-?zip\b/i, "7-Zip"],
  [/\bmoveit\b/i, "Progress"],
  [/\bjunos\b/i, "Juniper"],
  [/\bbig-?ip\b/i, "F5"],
];

/** KEV vendor spellings that name the same company today. */
const VENDOR_ALIASES: Record<string, string> = {
  "pulse secure": "ivanti", "pulsesecure": "ivanti", "mobileiron": "ivanti",
  "palo alto": "palo alto networks", "paloalto networks": "palo alto networks",
  // the same product under two KEV vendor names: "PHP / PHP" and "PHP Group / PHP"; "Langflow / Langflow" and
  // "IBM / Langflow"
  "php group": "php", "langflow": "ibm",
};

/**
 * Companies whose own name is not a product: a KEV entry spelled "<vendor> / <vendor>" for one of them
 * ("Microsoft / Microsoft", "Apache / Apache") names no product, so it is vague. Every other such entry names the
 * vendor's eponymous product ("OpenSSL / OpenSSL", "Samba / Samba", "Sudo / Sudo", "Notepad++ / Notepad++",
 * "Jenkins / Jenkins"), which is as specific as any other KEV product. The list: the companies of VENDOR_WORDS, and IBM.
 */
const UMBRELLA_VENDORS = new Set([
  "microsoft", "apache", "citrix", "fortinet", "cisco", "google", "adobe", "ivanti", "palo alto networks", "vmware",
  "oracle", "mozilla", "apple", "atlassian", "solarwinds", "sonicwall", "juniper", "f5", "zyxel", "zoho", "progress",
  "rarlab", "veeam", "sap", "ibm",
]);

/** Comparison form of a vendor name: lowercase, clean, with renamed companies folded together. */
export function normVendor(v: string | null | undefined): string {
  const s = lowerClean(v ?? "");
  return VENDOR_ALIASES[s] ?? s;
}

/** When the string names only the vendor, the product it usually means ("Apache 2.4.49" = Apache HTTP Server). */
const VENDOR_DEFAULT_PRODUCT: Record<string, string> = { apache: "HTTP Server" };

function firstMatch(table: [RegExp, string][], text: string): { vendor: string; re: RegExp } | null {
  let best: { vendor: string; re: RegExp; at: number; len: number } | null = null;
  for (const [re, vendor] of table) {
    const m = re.exec(text);
    if (!m) continue;
    if (!best || m.index < best.at || (m.index === best.at && m[0].length > best.len)) {
      best = { vendor, re, at: m.index, len: m[0].length };
    }
  }
  return best ? { vendor: best.vendor, re: best.re } : null;
}

// ---------- product types ----------

export type TypeRelation = "same" | "compatible" | "neutral" | "conflict";

/**
 * How two product types relate. The conflicts are the look-alike traps: a cloud service vs anything on-prem,
 * and an endpoint client vs a server, console or appliance. "unknown" is neutral.
 */
export function typeRelation(a: ProductType, b: ProductType): TypeRelation {
  if (a === "unknown" || b === "unknown") return "neutral";
  if (a === b) return "same";
  if (a === "cloud_service" || b === "cloud_service") return "conflict";
  const onPrem = (t: ProductType): boolean => t === "server" || t === "network_appliance";
  if ((a === "client" && onPrem(b)) || (b === "client" && onPrem(a))) return "conflict";
  return "compatible";
}

interface TypeRule { type: ProductType; re: RegExp; vendors?: string[]; not?: RegExp; }

/** Cues that the item is a hosted service, wherever they appear ("Exchange Online", "(M365 tenant)"). */
const STRONG_CLOUD = /\b(?:online|saas|tenant|on the web)\b/;
/** Microsoft's hosted suite: "M365", "O365", "Microsoft 365", "Office 365", "Office365", a bare "365". */
const SUITE_365 = /\b(?:m365|o365|(?:microsoft|office) ?365|365)\b/;
const SUITE_365_G = new RegExp(SUITE_365.source, "g");
/** In a bracketed note only the suite's names count: a bare "365" there is usually a count ("(365 users)"). */
const NOTE_365 = /\b(?:m365|o365|(?:microsoft|office) ?365)\b/;
/** "Office 365" written alone names the desktop suite (a client), like "365 Apps"; see detectProductType. */
const OFFICE_365 = /\boffice ?365\b/;
/** A product made for the suite, not the suite: "Veeam Backup for Microsoft 365", "Defender for Office 365". */
const FOR_365 = /\bfor (?:(?:microsoft|office) ?|m|o)?365\b/g;
/** The installed desktop apps of the suite; checked before any cloud cue. */
const DESKTOP_SUITE = /\b(?:(?:microsoft |office |m|o)?365 apps|proplus)\b/;
/** A bracketed note that only says "cloud" ("Exchange (cloud)")... */
const CLOUD_NOTE = /\bcloud\b/;
/** ...unless it names IaaS hosting, which runs the same software ("(cloud VM)", "(cloud hosted)", "(cloud VPX)"). */
const IAAS_NOTE = /\b(?:vms?|virtual machines?|instances?|hosts?|hosted|iaas|ec2|droplets?|vps|vpx|containers?|docker|kubernetes|k8s|images?|servers?)\b/;
/** Words that keep an item on-prem even when a cue says cloud ("Exchange Server 2019 (hybrid, M365 tenant)"). */
const ON_PREM = /\b(?:server|svr|srv|on-?prem(?:ises)?|self-?hosted|appliance)\b/;
/** The same in a bracketed note: a hybrid, on-prem or private-cloud deployment runs its own server. */
const ON_PREM_NOTE = /\b(?:hybrid|on-?prem(?:ises)?|self-?hosted|private cloud)\b/;
/** Software that is only ever run by its owner (web servers, hypervisors): a "(cloud)" note means where it is hosted. */
const SELF_HOSTED_ONLY = /\b(?:http server|httpd|apache2|nginx|tomcat|iis|internet information services|esxi?|hyper-v)\b/;
/**
 * Appliance-class servers (NetScaler ADC/Gateway and its VPX/MPX/SDX forms, Ivanti Sentry and Virtual Traffic Manager,
 * Cisco ISE): run as an appliance or a virtual appliance, never as a tenant service, so a cloud note means where it runs.
 */
const APPLIANCE_CLASS = /\b(?:netscaler|adc|application delivery controller|gateway|gw|vpx|mpx|sdx|sentry|traffic manager|identity services engine)\b/;
/** A "bundled in ..." clause names the host of a component, not where the component is hosted. */
const BUNDLED_RE = /^(?:bundled|embedded|shipped|included|packaged|vendored)\b/i;

// First match wins. Management consoles come before client words ("FortiClient EMS" is a server);
// specific products come before generic words; weak cloud cues ("365", "cloud") come after every on-prem cue.
const TYPE_RULES: TypeRule[] = [
  { type: "os", re: /\bchrome ?os\b/ },
  { type: "client", re: DESKTOP_SUITE },
  {
    type: "server",
    re: /\b(?:ems|epmm?|forti(?:manager|analyzer|siem)|manager|mgr|management|console|orchestrator|controller|panorama)\b/,
    not: /\b(?:download|package|file|display|boot) manager\b/,
  },
  {
    type: "network_appliance",
    re: /\b(?:forti(?:gate|os|proxy|web|mail|adc|sandbox|wifi|switch|ap)|pan-?os|asa|adaptive security appliance|firepower|ftd|nx-?os|ios[- ]?x[er]|junos|big-?ip|sonicos|sd-?wan|wanop|routers?|switch(?:es)?|firewall|fw|vpn (?:gateway|concentrator|appliance)|connect secure|policy secure|zta gateways?)\b/,
  },
  { type: "network_appliance", re: /\bios\b/, vendors: ["cisco"] },
  { type: "network_appliance", re: /\bics\b/, vendors: ["ivanti"] },
  {
    type: "library",
    re: /\b(?:log4j\w*|struts\w*|spring(?:[- ]core| framework|4shell)|commons-text|jackson-databind|openssl|libwebp|libcurl|zlib|net (?:framework|core)|jar|war|library|lib|sdk|maven|npm package|pypi package|python package)\b/,
  },
  {
    type: "client",
    re: /\b(?:forticlient|anyconnect|secure client|globalprotect (?:app|agent|client)|workspace app|workspace application|receiver|chrome|chromium|firefox|thunderbird|safari|internet explorer|edge|acrobat|reader|flash player|office|word|excel|powerpoint|outlook|publisher|wordpad|teams|skype|zoom|slack|webex|notepad\+\+|7-?zip|winrar|vlc|putty|filezilla|visual studio|silverlight|tools|workstation|fusion|horizon client|dropbox|onedrive|itunes|quicktime)(?![\w+])/,
  },
  {
    type: "os",
    re: /\b(?:windows|win ?(?:7|8|10|11)|win32k|macos|mac os|os x|ipados|ios|android|linux kernel|kernel|ubuntu|debian|rhel|red hat enterprise linux|centos|smbv[13]|csrss|afd\.sys|ntoskrnl)\b/,
  },
  {
    type: "server",
    re: /\b(?:server|svr|srv|(?<!key )exchange|sharepoint|iis|internet information services|http server|httpd|apache2|tomcat|nginx|vcenter|vcsa|esxi?|hyperflex|identity services engine|adc|netscaler|gateway|gw|storefront|xenmobile|sentry|activemq|solr|airflow|ofbiz|kylin|rocketmq|superset|flink|couchdb|apisix|coldfusion|blazeds|magento|experience manager|confluence|jira|jenkins|gitlab|moveit|active directory|domain controller|remote desktop services|session recording|sharefile|content collaboration|cloud foundation|appliance|daemon)\b/,
  },
  { type: "cloud_service", re: /\b(?:365|m365|o365|cloud|daas|as a service)\b/ },
  { type: "client", re: /\b(?:client|app|apps|application|agent|desktop|browser|viewer|player|plug-?in|extension|add-?in)\b/ },
];

function typeText(s: string): string {
  return ` ${lowerClean(s).replace(PLATFORM_RE, " ")} `;
}

/** The first matching rule's type; `noCloud` skips the cloud rule (a note's cloud cue is decided in detectProductType). */
function ruleType(text: string, vendor: string | null, noCloud = false): ProductType | null {
  if (!text.trim()) return null;
  for (const r of TYPE_RULES) {
    if (noCloud && r.type === "cloud_service") continue;
    if (r.vendors && (!vendor || !r.vendors.includes(vendor))) continue;
    if (r.not && r.not.test(text)) continue;
    if (r.re.test(text)) return r.type;
  }
  return null;
}

/**
 * Whether a cloud cue can make this main text a hosted service: only a product with no type of its own, a server
 * product (Exchange, SharePoint, Confluence have hosted editions) or one already typed cloud, and never software that
 * is only ever self-hosted or an appliance-class server. Clients, OSes, libraries and appliances stay what they are:
 * "Outlook (M365)" is the desktop Outlook, "FortiGate (Azure cloud)" is still FortiOS, "NetScaler ADC (Azure cloud)"
 * is still the NetScaler appliance.
 */
function hostable(m: string, base: ProductType | null): boolean {
  return !SELF_HOSTED_ONLY.test(m) && !APPLIANCE_CLASS.test(m) && (base === null || base === "server" || base === "cloud_service");
}

/**
 * The product type from the type lexicon. The desktop-suite names ("365 Apps", "ProPlus") are clients, checked first.
 * Then, unless the main text says server/on-prem, a cloud cue makes the item a cloud_service:
 * - "online", "SaaS", "tenant" in the main text ("Exchange Online");
 * - the 365 suite names in the main text ("Exchange 365", "M365 Exchange") when the product they qualify is hostable;
 *   the suite named alone is cloud, except "Office 365", which is the desktop suite;
 * - "online", "SaaS", "tenant", a named 365 suite (M365, O365, Microsoft/Office 365; a bare "365" in a note is a
 *   count, "(365 users)") or a plain "cloud", in a bracketed note ("Exchange (M365)", "Exchange (cloud)"), when the main
 *   product is hostable, the note names no IaaS host ("VM", "hosted", "VPX") or hybrid/on-prem/private-cloud set-up,
 *   and the row has no version (`opts.versioned`, from the main text or a note: a versioned install is self-managed,
 *   "Exchange 2019 CU12 (M365 tenant)" is the hybrid server). Callers can tell a note-only cue with cloudCueSource.
 * Otherwise the main text decides, and the bracketed context ("(laptops)", "(bundled in ... WAR)") is used only when
 * the main text says nothing, and never for a cloud type (a note's cloud cue is decided above, with its guards).
 */
export function detectProductType(
  main: string, context: string[] = [], vendor: string | null = null, opts: { versioned?: boolean } = {},
): ProductType {
  const m = typeText(main).replace(FOR_365, " ");
  const c = typeText(context.join(" ; "));
  if (DESKTOP_SUITE.test(m)) return "client";
  if (!ON_PREM.test(m)) {
    if (STRONG_CLOUD.test(m)) return "cloud_service";
    if (SUITE_365.test(m)) {
      const base = ruleType(m.replace(SUITE_365_G, " "), vendor); // the product the suite name qualifies
      if (base === null ? !OFFICE_365.test(m) : hostable(m, base)) return "cloud_service";
    }
    const n = typeText(context.filter((x) => !BUNDLED_RE.test(x)).join(" ; ")).replace(FOR_365, " ");
    const noteCloud = STRONG_CLOUD.test(n) || NOTE_365.test(n) || (CLOUD_NOTE.test(n) && !IAAS_NOTE.test(n));
    if (noteCloud && !ON_PREM_NOTE.test(n) && !opts.versioned && hostable(m, ruleType(m, vendor))) return "cloud_service";
  }
  return ruleType(m, vendor) ?? ruleType(c, vendor, true) ?? "unknown";
}

export type AssetContext = "endpoint" | "cloud" | "infrastructure" | null;

/** What kind of asset an inventory row's asset_type describes (laptop -> endpoint, firewall -> infrastructure). */
export function assetContext(assetType: string | null | undefined): AssetContext {
  const s = typeText(assetType ?? "");
  if (/\b(?:laptops?|desktops?|workstations?|pcs?|notebooks?|macbooks?|mobiles?|phones?|tablets?|endpoints?|kiosks?|thin clients?)\b/.test(s)) return "endpoint";
  if (/\b(?:tenant|saas|m365|o365)\b/.test(s)) return "cloud"; // plain "cloud" may be an IaaS VM: no constraint
  if (/\b(?:servers?|vms?|hosts?|firewalls?|routers?|switch(?:es)?|vpn|appliances?|gateways?|nas|san|hypervisors?)\b/.test(s)) return "infrastructure";
  return null;
}

/** True when a KEV product of this type cannot be what runs on this kind of asset. */
function assetConflict(asset: AssetContext, kevType: ProductType): boolean {
  if (asset === "endpoint") return kevType === "server" || kevType === "network_appliance";
  if (asset === "cloud") return kevType !== "cloud_service" && kevType !== "unknown";
  return false;
}

// ---------- tokens and aliases ----------

// Applied in order to " lowercase text " before splitting; the same pipeline runs on inventory strings and KEV
// names, so both sides meet in one vocabulary. The third field limits an alias to one vendor.
const PHRASE_ALIASES: [RegExp, string, string?][] = [
  [/\bapplication delivery controller\b/g, "adc"],
  [/\badaptive security appliance\b/g, "asa"],
  [/\b(?:secure firewall|firepower) threat defense\b/g, "ftd"],
  [/\binternet information services\b/g, "iis"],
  [/\bpulse (connect secure|policy secure)\b/g, "$1"],
  [/\b(connect|policy)secure\b/g, "$1 secure"],
  [/\blog4j(?:-?2|-core|-api)?\b/g, "log4j"],
  [/\bstruts-?2(?:-core)?\b/g, "struts 2"],
  [/\b(?:apache http server|apache2|httpd|http server)\b/g, "http server"],
  [/\bpan[- ]?os\b/g, "panos"],
  [/\bfortigate\b/g, "fortios"],
  [/\b(?:mac ?os ?x|os x|macos)\b/g, "macos"],
  [/\bchromium\b/g, "chrome"],
  [/\b(?:sccm|mecm|configmgr)\b/g, "configuration manager"],
  [/\bad ?fs\b/g, "active directory federation services"],
  [/\bvcsa\b/g, "vcenter server"],
  [/\besx\b/g, "esxi"],
  [/\b7-?zip\b/g, "7zip"],
  [/\bwin ?(7|8|10|11)\b/g, "windows $1"],
  [/\bie\b/g, "internet explorer"],
  [/\bms-?sql\b/g, "sql server"],
  [/\bsd[- ]?wan\b/g, "sdwan"],
  [/\bnx[- ]?os\b/g, "nxos"],
  [/\bios[- ]?xe\b/g, "iosxe"],
  [/\bios[- ]?xr\b/g, "iosxr"],
  [/\bbig[- ]?ip\b/g, "bigip"],
  [/\bics\b/g, "connect secure", "ivanti"],
];

const TOKEN_ALIASES = new Map<string, string>([
  ["svr", "server"], ["srv", "server"], ["servers", "server"],
  ["apps", "app"], ["application", "app"], ["applications", "app"],
  ["gw", "gateway"], ["gateways", "gateway"],
  ["mgr", "manager"], ["mgmt", "management"],
  ["fw", "firewall"], ["routers", "router"], ["switches", "switch"],
  ["svc", "service"], ["services", "service"],
  ["win", "windows"], ["exch", "exchange"],
]);

const STOPWORDS = new Set([
  "and", "or", "for", "the", "of", "on", "in", "a", "an", "with", "by", "to", "from", "at", "via", "into",
  "software", "series", "version", "ver", "build", "release", "latest", "inc", "ltd", "llc", "corp", "bit",
]);

/** Weak words: they help a match but cannot carry one on their own. */
const GENERIC = new Set([
  "server", "client", "app", "service", "manager", "management", "gateway", "appliance", "agent", "desktop", "web",
  "ui", "edition", "enterprise", "professional", "pro", "standard", "mobile", "suite", "platform", "core", "console",
  "api", "system", "engine", "products", "product", "multiple", "plugin", "module", "tool", "tools",
]);

function tokenWeight(t: string): number {
  if (/^\d+[a-z]{0,2}$/.test(t)) return 0.3; // numerals and hardware models: "10", "365", "60f"
  if (GENERIC.has(t)) return 0.5;
  return 1;
}

/**
 * Canonical product tokens: lowercase, platform qualifiers removed, phrase and word aliases applied,
 * stop words and single letters dropped, unique, in order of appearance.
 */
export function canonicalTokens(text: string, vendor: string | null = null): string[] {
  return tokenize(text, vendor, false);
}

/** The canonicalTokens pipeline; `keepLetters` keeps single-letter words ("X" in "Jenkins X"). */
function tokenize(text: string, vendor: string | null, keepLetters: boolean): string[] {
  let s = ` ${lowerClean(text).replace(PLATFORM_RE, " ")} `;
  for (const [re, rep, only] of PHRASE_ALIASES) {
    if (only && only !== vendor) continue;
    s = s.replace(re, rep);
  }
  const out: string[] = [];
  for (const raw of s.split(/[^a-z0-9+]+/)) {
    if (!raw || !/[a-z0-9]/.test(raw)) continue;
    if (!keepLetters && /^[a-z]$/.test(raw)) continue;
    const t = TOKEN_ALIASES.get(raw) ?? raw;
    if (STOPWORDS.has(t) || out.includes(t)) continue;
    out.push(t);
  }
  return out;
}

// ---------- parsing ----------

function tidy(s: string): string {
  return s
    .replace(/\s+/g, " ")
    .replace(/\s+,/g, ",")
    .replace(/^[\s,;:/|\-–—+.]+/, "")
    .replace(/[\s,;:/|\-–—.]+$/, "")
    .trim();
}

/** Split off bracketed context and "bundled in ..." clauses, which name a host or a note rather than the product. */
function splitContext(text: string): { main: string; context: string[] } {
  const context: string[] = [];
  // a "(4)" glued to a version number is part of it (Cisco "9.16(4)")
  let main = text.replace(/(?<!\d)[([{]([^()[\]{}]*)[)\]}]/g, (_m, inner: string) => {
    context.push(inner.trim());
    return " ";
  });
  main = main.replace(/\s[([{][^)\]}]*$/, (m) => { context.push(m.trim().slice(1)); return " "; }); // unclosed bracket
  main = main.replace(/\b(?:bundled|embedded|shipped|included|packaged|vendored)\s+(?:in|with|inside|into)\b.*$/i, (m) => {
    context.push(m.trim());
    return " ";
  });
  return { main, context: context.filter(Boolean) };
}

/**
 * Parse one messy inventory string.
 * - version: "2.14.1", "13.1-48.47", "2019 CU12", "8.6" (from "v8.6"), "7.0 U3", "22.4R2"; null when absent
 * - vendor_hint: KEV's vendor spelling, from a vendor word ("MS" -> Microsoft) or a product that implies it
 *   (FortiGate -> Fortinet, httpd -> Apache, NetScaler -> Citrix, PAN-OS -> Palo Alto Networks)
 * - product_hint: the product words as written, without vendor word, version, noise and bracketed context
 * - product_type: from the type lexicon (cloud_service, client, server, network_appliance, library, os, unknown)
 * - tokens: canonical, alias-expanded product tokens ("Exchange Svr" -> exchange, server)
 */
export function parseSoftware(raw: string): ParsedSoftware {
  const r = splitRow(raw);
  return {
    raw, vendor_hint: r.vendor, product_hint: r.product_hint, version: r.version, product_type: rowType(r, true), tokens: r.tokens,
  };
}

interface RowParts {
  main: string; context: string[]; version: string | null; vendor: string | null; vNorm: string | null;
  /** The vendor comes from the main text (a vendor word, or a product or platform that implies one), not a note. */
  vendorInMain: boolean;
  product_hint: string; tokens: string[];
}

/** The pieces of one inventory string: main text (no version, noise or notes), notes, version, vendor, hint, tokens. */
function splitRow(raw: string): RowParts {
  const text = cleanText(raw);
  const { main: withVersion, context } = splitContext(text);

  let { version, rest } = extractVersion(withVersion);
  if (!version) {
    for (const c of context) {
      const v = extractVersion(c).version;
      if (v) { version = v; break; }
    }
  }
  const main = stripNoise(rest);

  // vendor: a vendor word in the main text, else a product that implies one, else a vendor word in the context
  let vendor: string | null = null;
  let vendorInMain = false;
  let hintText = main;
  const word = firstMatch(VENDOR_WORDS, main);
  if (word) {
    vendor = word.vendor;
    vendorInMain = true;
    hintText = main.replace(new RegExp(word.re.source, "i"), " ");
  } else {
    const implied = firstMatch(PRODUCT_VENDOR, main)?.vendor ?? null;
    vendorInMain = implied !== null;
    vendor = implied ?? firstMatch(VENDOR_WORDS, context.join(" ; "))?.vendor ?? null;
  }
  const vNorm = vendor ? normVendor(vendor) : null;

  let product_hint = tidy(hintText);
  if (!product_hint && vNorm && VENDOR_DEFAULT_PRODUCT[vNorm]) product_hint = VENDOR_DEFAULT_PRODUCT[vNorm];
  const tokens = canonicalTokens(product_hint, vNorm);
  if (!product_hint) product_hint = tidy(main) || text;
  return { main, context, version, vendor, vNorm, vendorInMain, product_hint, tokens };
}

/**
 * The row's type, with its bracketed notes (`withNotes`) or from the main text alone. A version anywhere in the row,
 * main text or note, marks a self-managed install ("NetScaler ADC (cloud, 13.1-48.47)").
 */
function rowType(r: RowParts, withNotes: boolean): ProductType {
  const t = detectProductType(r.main, withNotes ? r.context : [], r.vNorm, { versioned: r.version !== null });
  if (t === "unknown" && r.tokens.length) return detectProductType(r.product_hint, [], r.vNorm); // "Apache 2.4.49"
  return t;
}

/**
 * Where a parsed row's cloud_service type comes from: "main" when its main text says so ("Exchange Online",
 * "M365 Exchange", "Exchange 365"), "note" when only a bracketed note does ("Exchange (M365)", "ActiveMQ (cloud)"),
 * null when the row is not typed cloud_service. A note-only cue is weaker evidence: it may only say where an on-prem
 * product is hosted, so the vote never turns it into a confident "no KEV product" (see normaliserVote).
 */
export function cloudCueSource(parsed: ParsedSoftware): "main" | "note" | null {
  if (parsed?.product_type !== "cloud_service") return null;
  return mainTextType(parsed) === "cloud_service" ? "main" : "note";
}

/** The type the row would have without its bracketed notes and "bundled in" clauses. */
function mainTextType(parsed: ParsedSoftware): ProductType {
  return rowType(splitRow(typeof parsed?.raw === "string" ? parsed.raw : ""), false);
}

// ---------- families ----------

const WINDOWS_COMPONENTS = new RegExp(
  "^(?:windows\\b|win32k\\b|smbv[13]\\b|client-server run-time subsystem|ancillary function driver|dwm core library|" +
  "task scheduler|graphics device interface|graphics component|directx\\b|atm font driver|enhanced cryptographic provider|" +
  "http protocol stack|http\\.sys|streaming service|winverifytrust|kerberos key distribution center|netlogon|" +
  "internet key exchange|cng key isolation|com\\+ event system|update notification manager|smartscreen|" +
  "input method editor|hyper-v|mshtml|xml core services|remote desktop services|mscomctl)",
);

// Families with several KEV spellings, written out; every other pair falls through to the generic rule.
// The rules also name the products KEV lists second in a combo ("FortiOS and FortiProxy", "IOS, XR, and XE Software"),
// because familiesOf applies them to each product of a combo.
const FAMILY_RULES: { vendor: string; re: RegExp; family: string }[] = [
  { vendor: "citrix", re: /^netscaler sd-?wan\b/, family: "citrix:sd-wan" },
  { vendor: "citrix", re: /\b(?:netscaler|application delivery controller|adc|gateway)\b/, family: "citrix:netscaler-adc-gateway" },
  { vendor: "citrix", re: /\b(?:workspace|receiver)\b/, family: "citrix:workspace-app" },
  { vendor: "microsoft", re: /^exchange(?: server)?$/, family: "microsoft:exchange-server" },
  { vendor: "microsoft", re: /^sharepoint(?: server)?$/, family: "microsoft:sharepoint-server" },
  { vendor: "microsoft", re: /^internet explorer\b/, family: "microsoft:internet-explorer" },
  { vendor: "microsoft", re: /^(?:office )?outlook$/, family: "microsoft:outlook" },
  { vendor: "microsoft", re: WINDOWS_COMPONENTS, family: "microsoft:windows" },
  { vendor: "fortinet", re: /^fortios\b/, family: "fortinet:fortios" },
  { vendor: "fortinet", re: /^fortiproxy\b/, family: "fortinet:fortiproxy" },
  { vendor: "apache", re: /^log4j/, family: "apache:log4j" },
  { vendor: "apache", re: /^struts 1$/, family: "apache:struts-1" },
  { vendor: "apache", re: /^struts\b/, family: "apache:struts" },
  { vendor: "apache", re: /^airflow\b/, family: "apache:airflow" },
  { vendor: "apache", re: /^(?:http server|httpd)\b/, family: "apache:http-server" },
  { vendor: "adobe", re: /\bacrobat\b|^reader\b/, family: "adobe:acrobat-reader" },
  { vendor: "adobe", re: /^flash player\b/, family: "adobe:flash-player" },
  { vendor: "adobe", re: /\bmagento\b|^commerce\b/, family: "adobe:commerce-magento" },
  { vendor: "google", re: /^chrom(?:e|ium)\b/, family: "google:chromium" },
  { vendor: "ivanti", re: /\bcloud services? appliance\b|\bcsa\b/, family: "ivanti:cloud-services-appliance" },
  { vendor: "ivanti", re: /\b(?:endpoint manager mobile|epmm|mobileiron)\b/, family: "ivanti:endpoint-manager-mobile" },
  { vendor: "ivanti", re: /^endpoint manager\b/, family: "ivanti:endpoint-manager" },
  { vendor: "ivanti", re: /^(?:pulse )?connect secure\b/, family: "ivanti:connect-secure" },
  { vendor: "ivanti", re: /^(?:pulse )?policy secure\b/, family: "ivanti:policy-secure" },
  { vendor: "cisco", re: /\badaptive security appliance\b|\basa\b/, family: "cisco:asa" },
  { vendor: "cisco", re: /\b(?:firepower|secure firewall) threat defense\b|^ftd\b/, family: "cisco:ftd" },
  { vendor: "cisco", re: /^(?:ios )?xr\b/, family: "cisco:ios-xr" },
  { vendor: "cisco", re: /^(?:ios|xe)\b/, family: "cisco:ios" },
  { vendor: "cisco", re: /\bsd-?wan\b/, family: "cisco:sd-wan" },
  { vendor: "cisco", re: /\brv series\b|\brv\d{3}\b.*\brouters?\b/, family: "cisco:rv-routers" },
  { vendor: "vmware", re: /^esxi\b/, family: "vmware:esxi" },
  { vendor: "vmware", re: /^vcenter server\b/, family: "vmware:vcenter-server" },
  { vendor: "palo alto networks", re: /^pan-?os\b/, family: "palo-alto-networks:pan-os" },
  // eponymous products whose KEV entries are split across spellings (the vendor prefix is already stripped here):
  // Jenkins core with its CLI, UI and Stapler web framework (the plugins stay separate products); Exim, "Exim
  // Internet Mailer" and Exim's "Mail Transfer Agent (MTA)"; GitLab, "GitLab CE/EE" and the CE/EE edition names
  { vendor: "jenkins", re: /^(?:jenkins$|command line interface\b|user interface\b|stapler\b)/, family: "jenkins:jenkins" },
  { vendor: "exim", re: /^(?:exim|internet mailer|mail transfer agent)\b/, family: "exim:exim" },
  { vendor: "gitlab", re: /^(?:gitlab\b|ce\/ee\b|community\b|enterprise editions?\b)/, family: "gitlab:gitlab" },
];

const COMBO_SPLIT = /\s*,\s*(?:and\s+)?|\s+and\s+|\s*&\s*|\s+\/\s+/;

function stripLeadingVendor(productLower: string, vNorm: string): string {
  if (vNorm && productLower !== vNorm && productLower.startsWith(`${vNorm} `)) return productLower.slice(vNorm.length + 1);
  return productLower;
}

/**
 * A KEV entry that names no product: an empty name, "Multiple Products", or an umbrella company's own name
 * ("Microsoft / Microsoft"). A vendor-named entry of any other vendor is its eponymous product ("OpenSSL / OpenSSL").
 */
function isVague(productLower: string, vNorm: string): boolean {
  if (!productLower || /\bmultiple products\b/.test(productLower)) return true;
  return productLower === vNorm && UMBRELLA_VENDORS.has(vNorm);
}

/**
 * A vendor-named product ("OpenSSL / OpenSSL", "Sudo / Sudo", "Langflow / Langflow" and "IBM / Langflow"): its name is
 * a brand, not a description, so a neighbouring brand is a different product ("OpenSSH" is not OpenSSL, "GitLab Runner"
 * is not GitLab). Such a name is matched exactly, never through a typo, and the vote names it only when the row adds no
 * other product words (see eponymousDoubt).
 */
function isEponymous(productLower: string, vNorm: string): boolean {
  if (isVague(productLower, vNorm)) return false;
  return productLower === vNorm || VENDOR_ALIASES[productLower] === vNorm;
}

/**
 * Words that qualify a vendor-named product without naming another one: editions and release tracks ("GitLab CE",
 * "Jenkins LTS", "Samba server") and distribution packaging ("openssl-libs", "samba-common", "sudo (Ubuntu package)").
 */
const SAME_PRODUCT_WORDS = new Set([
  "server", "core", "edition", "editions", "community", "enterprise", "ce", "ee", "oss", "lts", "stable", "standard",
  "pro", "professional",
  "package", "pkg", "deb", "rpm", "dfsg", "lib", "libs", "common", "bin", "ubuntu", "debian", "rhel", "centos", "alpine",
  "fedora", "suse",
]);

/**
 * One key per product family across KEV's spellings, "<vendor>:<product>" in slug form. Examples:
 * every Citrix ADC/NetScaler/Gateway spelling -> "citrix:netscaler-adc-gateway"; "Exchange" and "Exchange Server"
 * -> "microsoft:exchange-server"; "Windows " -> "microsoft:windows"; the FortiOS combos -> "fortinet:fortios".
 * A vendor's eponymous product has its own family ("OpenSSL / OpenSSL" -> "openssl:openssl"); an umbrella
 * company's own name names none ("Microsoft / Microsoft" -> "microsoft:multiple-products").
 * Otherwise: the first product of a combo, without parentheses, platform qualifiers or "software"/"series".
 */
export function familyOf(p: KevPair): string {
  const vNorm = normVendor(p.vendor);
  const vSlug = slugify(vNorm) || "unknown";
  const prod = stripLeadingVendor(lowerClean(p.product), vNorm);
  for (const r of FAMILY_RULES) if (r.vendor === vNorm && r.re.test(prod)) return r.family;
  if (isVague(prod, vNorm)) return `${vSlug}:multiple-products`;
  const main = prod.replace(/\([^)]*\)/g, " ").replace(PLATFORM_RE, " ").trim();
  const first = main.split(COMBO_SPLIT).find((x) => x.trim()) ?? main;
  const slug = slugify(first.replace(/\b(?:software|series)\b/g, " "));
  if (!slug || (slug === vSlug && UMBRELLA_VENDORS.has(vNorm))) return `${vSlug}:multiple-products`;
  return `${vSlug}:${slug}`;
}

/**
 * Every pair in the list whose own family (familyOf, the first product of a combo) is this one: the spellings of one
 * family. To fetch a resolved row's KEV rows, use pairsMentioning, which also finds the combos that list the product
 * second (".NET Framework, SharePoint, Visual Studio" for SharePoint).
 */
export function pairsInFamily(family: string, pairs: KevPair[]): KevPair[] {
  return pairs.filter((p) => familyOf(p) === family);
}

/** The products a KEV name lists, lowercase, without brackets or platform qualifiers: "ESXi, Workstation, and Fusion". */
function comboParts(prodLower: string): string[] {
  return prodLower.replace(/\([^)]*\)/g, " ").replace(PLATFORM_RE, " ").split(COMBO_SPLIT).map((x) => x.trim()).filter(Boolean);
}

/** The type of one product named by a KEV pair; the Windows components (Win32k, SMBv1, CSRSS, ...) are parts of the OS. */
function productTypeOf(vendor: string, productLower: string): ProductType {
  if (familyOf({ vendor, product: productLower }) === "microsoft:windows") return "os";
  return detectProductType(productLower, [], normVendor(vendor));
}

/**
 * The type lexicon applied to a KEV pair: "Exchange Server" -> server; "FortiClient EMS" -> server;
 * "Workspace Application and Receiver for Windows" -> client. A combo takes the type of its first typed product
 * ("FortiOS and FortiProxy" -> network_appliance), or the whole name's. A combo whose products' types conflict
 * ("ESXi and Workstation": a server and a client) has no single type: "unknown", which is neutral. For the type of
 * the product a given row matched, use matchedKevPart.
 */
export function kevProductType(p: KevPair): ProductType {
  if (familyOf(p) === "microsoft:windows") return "os";
  const vNorm = normVendor(p.vendor);
  const prod = stripLeadingVendor(lowerClean(p.product), vNorm);
  const known = comboParts(prod).map((x) => productTypeOf(p.vendor, x)).filter((t) => t !== "unknown");
  if (!known.length) return detectProductType(prod, [], vNorm);
  if (known.some((a) => known.some((b) => typeRelation(a, b) === "conflict"))) return "unknown";
  return known[0];
}

/**
 * Every family a KEV pair names: its own (familyOf) first, then, for a combo, each listed product's
 * ("ESXi, Workstation, and Fusion" -> vmware:esxi, vmware:workstation, vmware:fusion).
 */
export function familiesOf(p: KevPair): string[] {
  return [...kevInfo(p).families];
}

/**
 * Every pair that names the family, as its own family or as a later product of a combo. These are the KEV spellings
 * to fetch for a row resolved to that family: for SharePoint, "SharePoint", "SharePoint Server" and
 * ".NET Framework, SharePoint, Visual Studio"; for VMware Workstation, "ESXi and Workstation" and
 * "ESXi, Workstation, and Fusion".
 */
export function pairsMentioning(family: string, pairs: KevPair[]): KevPair[] {
  return pairs.filter((p) => p && typeof p.vendor === "string" && typeof p.product === "string" && kevInfo(p).families.includes(family));
}

// ---------- similarity ----------

/** Jaro-Winkler similarity in [0, 1] (prefix scale 0.1, prefix length up to 4). */
export function jaroWinkler(a: string, b: string): number {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;
  const range = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);
  const aHit = new Array<boolean>(a.length).fill(false);
  const bHit = new Array<boolean>(b.length).fill(false);
  let m = 0;
  for (let i = 0; i < a.length; i++) {
    const lo = Math.max(0, i - range);
    const hi = Math.min(i + range + 1, b.length);
    for (let j = lo; j < hi; j++) {
      if (bHit[j] || a[i] !== b[j]) continue;
      aHit[i] = true; bHit[j] = true; m++;
      break;
    }
  }
  if (!m) return 0;
  let t = 0;
  let k = 0;
  for (let i = 0; i < a.length; i++) {
    if (!aHit[i]) continue;
    while (!bHit[k]) k++;
    if (a[i] !== b[k]) t++;
    k++;
  }
  const jaro = (m / a.length + m / b.length + (m - t / 2) / m) / 3;
  let l = 0;
  while (l < 4 && l < a.length && l < b.length && a[l] === b[l]) l++;
  return jaro + l * 0.1 * (1 - jaro);
}

const sumWeights = (ts: string[]): number => ts.reduce((s, t) => s + tokenWeight(t), 0);

/** At most one edit apart: a substitution, an insertion/deletion, or two adjacent letters swapped. */
function withinOneEdit(a: string, b: string): boolean {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true;
    return i + 1 < a.length && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  }
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}

/**
 * A typo of a long word ("exchnage"), not a different product: words two edits apart ("workplace"/"workspace"),
 * a different first letter ("vcenter"/"center"), short codes ("iosxe"/"iosxr") or numbered names ("smbv1"/"smbv3").
 * Never applied to a vendor-named product's name: "openssh" is not a typo of "openssl" (see isEponymous).
 */
const isTypo = (a: string, b: string): boolean =>
  a.length >= 6 && b.length >= 6 && a[0] === b[0] && !/\d/.test(a + b) && withinOneEdit(a, b);

/** Weighted Dice overlap; a one-letter typo of a long token counts as 0.9 of a match, unless `typos` is false. */
function softDice(P: string[], Q: string[], typos = true): { dice: number; matched: string[] } {
  if (!P.length || !Q.length) return { dice: 0, matched: [] };
  const used = new Array<boolean>(P.length).fill(false);
  let inter = 0;
  const matched: string[] = [];
  for (const q of Q) {
    let bi = -1;
    let bm = 0;
    for (let i = 0; i < P.length; i++) {
      if (used[i]) continue;
      let m = 0;
      if (P[i] === q) m = 1;
      else if (typos && isTypo(P[i], q)) m = 0.9;
      if (m > bm) { bm = m; bi = i; }
    }
    if (bi >= 0) {
      used[bi] = true;
      inter += (bm * (tokenWeight(P[bi]) + tokenWeight(q))) / 2;
      matched.push(P[bi] === q ? q : `${P[bi]}~${q}`);
    }
  }
  return { dice: (2 * inter) / (sumWeights(P) + sumWeights(Q)), matched };
}

// ---------- scoring ----------

/**
 * One way a KEV name can be matched: the whole name, one product of a combo, or a bracketed abbreviation. Each carries
 * the type and family of the product it names, so a row that matches "Workstation" in "ESXi and Workstation" is
 * compared with a client, not with the server ESXi.
 */
interface KevPart {
  tokens: string[]; str: string; penalty: number; text: string; whole: boolean; type: ProductType; family: string;
}
interface KevInfo {
  vNorm: string; vendorTokens: string[]; parts: KevPart[]; type: ProductType; family: string; families: string[];
  vague: boolean; eponymous: boolean; key: string; clean: boolean;
}

const KEV_MEMO = new Map<string, KevInfo>();

function kevInfo(p: KevPair): KevInfo {
  const memoKey = `${p.vendor}\u0000${p.product}`;
  const hit = KEV_MEMO.get(memoKey);
  if (hit) return hit;
  const vNorm = normVendor(p.vendor);
  const prod = stripLeadingVendor(lowerClean(p.product), vNorm);
  const type = kevProductType(p);
  const family = familyOf(p);
  const parens: string[] = [];
  const main = prod.replace(/\(([^)]*)\)/g, (_m, x: string) => { parens.push(x); return " "; }).replace(PLATFORM_RE, " ");
  const combo = main.split(COMBO_SPLIT).map((x) => x.trim()).filter(Boolean);
  const isCombo = combo.length > 1;
  // A product's own type, or the pair's when the lexicon has none for it ("Neurons" in an appliance combo).
  const typeOf = (txt: string): ProductType => {
    const own = productTypeOf(p.vendor, txt);
    return own !== "unknown" ? own : type;
  };
  // The whole name, each product of a combo (its own family) and each bracketed abbreviation (the pair's family,
  // "(ASA)", "(EPM)") are alternatives.
  const texts: Omit<KevPart, "tokens" | "str">[] = [{ text: main.replace(/\s+/g, " ").trim(), penalty: 1, whole: true, type, family }];
  if (isCombo) {
    for (const c of combo) texts.push({ text: c, penalty: 0.97, whole: false, type: typeOf(c), family: familyOf({ vendor: p.vendor, product: c }) });
  }
  for (const x of parens) texts.push({ text: x, penalty: 0.97, whole: false, type: typeOf(x), family });
  const parts: KevPart[] = [];
  const seen = new Set<string>();
  for (const t of texts) {
    const tokens = canonicalTokens(t.text, vNorm);
    const str = tokens.join(" ");
    if (!tokens.length || seen.has(str)) continue;
    seen.add(str);
    parts.push({ ...t, tokens, str });
  }
  const families = [family];
  if (isCombo) {
    for (const c of combo) {
      const f = familyOf({ vendor: p.vendor, product: c });
      if (!families.includes(f)) families.push(f);
    }
  }
  const info: KevInfo = {
    vNorm,
    vendorTokens: canonicalTokens(vNorm),
    parts,
    type,
    family,
    families,
    vague: isVague(prod, vNorm),
    eponymous: isEponymous(prod, vNorm),
    key: `${vNorm}|${lowerClean(p.product)}`,
    clean: cleanText(p.product) === p.product && cleanText(p.vendor) === p.vendor,
  };
  KEV_MEMO.set(memoKey, info);
  return info;
}

interface InvCtx {
  tokens: string[]; str: string; vNorm: string | null; rawTokens: Set<string>; type: ProductType;
  /** The product words with single letters kept ("jenkins x"), for eponymousDoubt. */
  words: string[];
  /** The vendor named or implied by the main text, normalised; null when there is none or it comes from a note. */
  mainVendor: string | null;
}

/** A version wildcard ("1.1.x", "8.x"): not a product word. */
const VERSION_WILDCARD = /(?<![\w.])\d+(?:\.\d+)*\.[x*](?![\w.])/gi;

function invContext(parsed: ParsedSoftware | null | undefined): InvCtx {
  const tokens = Array.isArray(parsed?.tokens) ? parsed.tokens : [];
  const vNorm = parsed?.vendor_hint ? normVendor(parsed.vendor_hint) : null;
  const hint = typeof parsed?.product_hint === "string" ? parsed.product_hint.replace(VERSION_WILDCARD, " ") : "";
  const words = hint ? tokenize(hint, vNorm, true) : tokens;
  let mainVendor: string | null = null;
  if (vNorm && typeof parsed?.raw === "string") {
    const r = splitRow(parsed.raw);
    if (r.vendorInMain && r.vNorm === vNorm) mainVendor = vNorm;
  }
  return {
    tokens,
    str: tokens.join(" "),
    vNorm,
    rawTokens: new Set(canonicalTokens(parsed?.raw ?? "")),
    type: parsed?.product_type ?? "unknown",
    words,
    mainVendor,
  };
}

type VendorRel = "match" | "mismatch" | "unknown";
interface PairScore {
  score: number; name: number; dice: number; jw: number; matched: string[];
  vendor: VendorRel; typeRel: TypeRelation; kevType: ProductType; family: string; vague: boolean;
  /** The family of the product the row matched (a combo's second product has its own); `part` is that product. */
  matchFamily: string; part: string | null;
}

const VENDOR_FACTOR: Record<VendorRel, number> = { match: 1, unknown: 0.4, mismatch: 0 };
const TYPE_FACTOR: Record<TypeRelation, number> = { same: 1, compatible: 0.5, neutral: 0.5, conflict: 0 };
const round = (x: number, d: number): number => Math.round(x * 10 ** d) / 10 ** d;
const clamp01 = (x: number): number => Math.min(1, Math.max(0, x));

/** The alternative of the KEV name that best matches the row's tokens (the whole name when nothing matches). */
function bestPart(ctx: InvCtx, info: KevInfo): { name: number; dice: number; jw: number; matched: string[]; part: KevPart | null } {
  let best = { name: 0, dice: 0, jw: 0, matched: [] as string[], part: info.parts[0] ?? null };
  for (const part of info.parts) {
    const { dice, matched } = softDice(ctx.tokens, part.tokens, !info.eponymous); // a brand name is matched exactly
    const jw = ctx.str && part.str ? jaroWinkler(ctx.str, part.str) : 0;
    const name = (0.8 * dice + 0.2 * jw) * part.penalty;
    if (name > best.name) best = { name, dice, jw, matched, part };
  }
  return best;
}

function scorePair(ctx: InvCtx, info: KevInfo): PairScore {
  const best = bestPart(ctx, info);
  // the type and family of the product the row matched, not of the combo's first product
  const kevType = best.part ? best.part.type : info.type;
  const matchFamily = best.part ? best.part.family : info.family;
  let vendor: VendorRel = "unknown";
  if (ctx.vNorm) vendor = ctx.vNorm === info.vNorm ? "match" : "mismatch";
  else if (info.vendorTokens.length && info.vendorTokens.every((t) => ctx.rawTokens.has(t))) vendor = "match";
  const typeRel = typeRelation(ctx.type, kevType);
  let score = 0.75 * best.name + 0.15 * VENDOR_FACTOR[vendor] + 0.1 * TYPE_FACTOR[typeRel];
  if (typeRel === "conflict") score *= 0.6;
  if (info.vague) score *= 0.5;
  return {
    score: clamp01(score), name: best.name, dice: best.dice, jw: best.jw, matched: best.matched,
    vendor, typeRel, kevType, family: info.family, vague: info.vague,
    matchFamily, part: best.part && !best.part.whole ? best.part.text : null,
  };
}

/** Two scored pairs name the same product: one family, or the same matched product ("SharePoint" in a combo). */
const sameProduct = (a: PairScore, b: PairScore): boolean => a.family === b.family || a.matchFamily === b.matchFamily;

function reasonOf(ctx: InvCtx, s: PairScore): string {
  const bits = [
    `name ${round(s.name, 2)} (tokens ${s.matched.length ? s.matched.join(" ") : "none"}, dice ${round(s.dice, 2)}, jw ${round(s.jw, 2)})`,
    s.vendor === "match" ? "vendor match" : s.vendor === "mismatch" ? "vendor mismatch" : "vendor unknown",
    s.typeRel === "conflict" ? `type conflict: ${ctx.type} vs ${s.kevType}` : `type ${ctx.type}/${s.kevType} ${s.typeRel}`,
  ];
  if (s.part !== null) bits.push(`via combo part "${s.part}" (${s.matchFamily})`);
  if (s.vague) bits.push("vague KEV entry");
  return bits.join("; ");
}

/**
 * For one row and one KEV pair: the product of the pair the row matched, with that product's family and type
 * ("VMware Workstation 17.5" vs "ESXi and Workstation" -> "workstation", vmware:workstation, client). Use it for the
 * critic's KEV type (`kev_type`) and to pick the family whose KEV rows to fetch (pairsMentioning).
 */
export function matchedKevPart(parsed: ParsedSoftware, p: KevPair): { part: string; family: string; product_type: ProductType } {
  const info = kevInfo(p);
  const best = bestPart(invContext(parsed), info);
  if (!best.part) return { part: lowerClean(p.product), family: info.family, product_type: info.type };
  return { part: best.part.text, family: best.part.family, product_type: best.part.type };
}

const cmpStr = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The top-k KEV candidate pairs for one parsed row, best first, each with its family, score in [0, 1] and reason.
 * Score = 0.75 x name (alias-expanded weighted token Dice 0.8 + Jaro-Winkler 0.2, best over the KEV name, its combo
 * parts and bracketed abbreviation) + 0.15 x vendor fit + 0.10 x type fit; x0.6 on a type conflict; x0.5 for a vague
 * KEV entry ("Multiple Products"); a vendor-named product's name gets no typo credit. Spellings that differ only in case
 * or spacing appear once (the clean one), at most family_cap spellings per family. Same-vendor look-alikes stay in the
 * list on purpose: the jury and the critic must see them. Pairs with no name overlap and no vendor fit are left out.
 */
export function topCandidates(parsed: ParsedSoftware, pairs: KevPair[], k = 12): Candidate[] {
  if (!Array.isArray(pairs) || !pairs.length || !(k > 0)) return [];
  const ctx = invContext(parsed);
  if (!ctx.tokens.length && !ctx.vNorm) return [];
  const unique = new Map<string, { p: KevPair; info: KevInfo }>();
  for (const p of pairs) {
    if (!p || typeof p.vendor !== "string" || typeof p.product !== "string" || !p.product.trim()) continue;
    const info = kevInfo(p);
    const prev = unique.get(info.key);
    // keep the clean spelling; between equals, the smallest string, so the input order never matters
    const better = !prev || (info.clean !== prev.info.clean ? info.clean
      : cmpStr(`${p.product}\u0000${p.vendor}`, `${prev.p.product}\u0000${prev.p.vendor}`) < 0);
    if (better) unique.set(info.key, { p, info });
  }
  const scored = [...unique.values()]
    .map(({ p, info }) => ({ p, s: scorePair(ctx, info) }))
    .filter(({ s }) => s.dice > 0 || s.vendor === "match" || s.jw >= 0.85)
    .sort((a, b) => b.s.score - a.s.score || cmpStr(a.s.family, b.s.family) || cmpStr(a.p.product, b.p.product) || cmpStr(a.p.vendor, b.p.vendor));
  const perFamily = new Map<string, number>();
  const out: Candidate[] = [];
  for (const { p, s } of scored) {
    if (out.length >= k) break;
    const n = perFamily.get(s.family) ?? 0;
    if (n >= T.family_cap) continue;
    perFamily.set(s.family, n + 1);
    out.push({ vendor: p.vendor, product: p.product, family: s.family, score: round(s.score, 3), reason: reasonOf(ctx, s) });
  }
  return out;
}

// ---------- the normaliser's vote ----------

/** How to read a vote: a named pair, a confident "no KEV product matches", or an abstention. */
export function voteKind(v: Pick<JurorVote, "vendor" | "product" | "confidence">): "match" | "no_match" | "abstain" {
  if (v.vendor && v.product) return "match";
  return v.confidence >= T.no_match_confidence_min ? "no_match" : "abstain";
}

/**
 * The deterministic vote. It names a pair only when the best type-compatible candidate scores >= match_min and
 * beats every other family by >= margin_min (a combo is compared through the product the row matched, so a combo that
 * lists the same product is not a rival, and "Workstation" in "ESXi and Workstation" is typed as a client).
 * A candidate is blocked when its type conflicts with the row's
 * (cloud vs on-prem, client vs server/console/appliance), when the asset cannot run it (a laptop running a server
 * product), or when the KEV entry is vague ("Multiple Products", "Microsoft / Microsoft"; a vendor's eponymous product
 * such as "OpenSSL / OpenSSL" is not vague). Otherwise the vote is null: confidence >= no_match_confidence_min means
 * "no KEV product matches" (nothing resembles it, or only a blocked look-alike does); lower means "unsure", which is
 * also the vote when a vague entry resembles the row (KEV may list the product under that name).
 * A vendor-named product ("OpenSSL / OpenSSL", "GitLab / GitLab") is matched by its exact name, never through a typo
 * ("OpenSSH" is a confident no-match, not OpenSSL), and the vote abstains when the row may be a neighbouring product of
 * the brand ("GitLab Runner", "jQuery UI", "Jenkins X") or another vendor's ("Sudo for Windows"): see eponymousDoubt.
 * A cloud type that rests only on a bracketed note ("Exchange (M365)", "ActiveMQ (cloud)") may block a match, but never
 * earns a confident "no KEV product": the note may only say where an on-prem product is hosted. Such a row abstains when
 * it has a look-alike, or when its main text alone would have matched or abstained; the owner is asked.
 * Confidence never reaches 1: this is a rule-based reader, not ground truth.
 */
export function normaliserVote(row: InventoryRow, parsed: ParsedSoftware, cands: Candidate[]): JurorVote {
  const base = { row_id: row?.row_id ?? "", juror: "normaliser" as const };
  const nullVote = (confidence: number): JurorVote => ({
    ...base, vendor: null, product: null, product_type: parsed?.product_type ?? "unknown", confidence,
  });
  const ctx = invContext(parsed);
  if (!ctx.tokens.length) return nullVote(CONF_EMPTY);
  const list = (Array.isArray(cands) ? cands : []).filter((c) => c && typeof c.vendor === "string" && typeof c.product === "string");
  if (!list.length) return nullVote(CONF_NO_MATCH);

  const asset = assetContext(row?.asset_type);
  const b = ballot(ctx, list, asset);
  if (b.pick) {
    return {
      ...base,
      vendor: b.pick.vendor,
      product: b.pick.product,
      product_type: ctx.type !== "unknown" ? ctx.type : b.kevType,
      confidence: b.confidence,
    };
  }
  // fail closed on a note-only cloud cue: "NetScaler ADC (Azure cloud)" must not become a confident "no KEV product"
  if (b.confidence >= T.no_match_confidence_min && ctx.type === "cloud_service") {
    const mainType = mainTextType(parsed);
    if (mainType !== "cloud_service") {
      if (b.confidence === CONF_LOOKALIKE) return nullVote(CONF_ABSTAIN);
      const alt = ballot({ ...ctx, type: mainType }, list, asset);
      if (alt.pick || alt.confidence < T.no_match_confidence_min) return nullVote(CONF_ABSTAIN);
    }
  }
  return nullVote(b.confidence);
}

/**
 * Why a row that matched a vendor-named KEV product may be another product of that brand, or another company's product
 * of the same name: the main text names a different vendor ("Sudo for Windows" is Microsoft's), or the row has product
 * words the KEV name does not account for ("runner" in "GitLab Runner", "ui" in "jQuery UI", "lfs" in "Git LFS", "x" in
 * "Jenkins X", "desktop client" in "ownCloud desktop client"). Not counted: words of the same family's other KEV
 * spellings in the candidate list ("ce" in "GitLab CE", "cli" in "Jenkins CLI", "mta" in "Exim MTA"), the vendor's names,
 * edition and packaging words (SAME_PRODUCT_WORDS), "v" and anything with a digit (versions, builds). Returns the reason,
 * or null when the match stands. Only vendor-named entries are checked: their name is a brand, so a longer name built on
 * it is a different product as often as not, and KEV lists the brand's own product only.
 */
function eponymousDoubt(ctx: InvCtx, pick: Candidate, list: Candidate[]): string | null {
  const info = kevInfo(pick);
  if (!info.eponymous) return null;
  if (ctx.mainVendor && ctx.mainVendor !== info.vNorm) return `the row names another vendor (${ctx.mainVendor})`;
  const known = new Set<string>();
  for (const c of list) {
    const ci = kevInfo(c);
    if (!ci.families.includes(info.family)) continue;
    for (const part of ci.parts) for (const t of part.tokens) known.add(t);
    for (const t of [...ci.vendorTokens, ...canonicalTokens(c.vendor)]) known.add(t);
  }
  // the vendor's other KEV names ("PHP Group" for PHP), whose spellings topCandidates may have folded into one
  for (const [alias, to] of Object.entries(VENDOR_ALIASES)) if (to === info.vNorm) for (const t of canonicalTokens(alias)) known.add(t);
  const extra = ctx.words.filter((w) => !known.has(w) && !SAME_PRODUCT_WORDS.has(w) && w !== "v" && !/\d/.test(w));
  return extra.length ? `words beyond the KEV name: ${extra.join(" ")}` : null;
}

/** One reading of the candidates for a row of a given type: a pick (with its confidence), or a null vote's confidence. */
function ballot(ctx: InvCtx, list: Candidate[], asset: AssetContext): { pick: Candidate | null; kevType: ProductType; confidence: number } {
  const none = (confidence: number) => ({ pick: null, kevType: "unknown" as ProductType, confidence });
  const scored = list
    .map((c) => {
      const s = scorePair(ctx, kevInfo(c));
      const blocked = s.typeRel === "conflict" || assetConflict(asset, s.kevType) || s.vague;
      return { c, s, blocked };
    })
    .sort((a, b) => b.s.score - a.s.score || cmpStr(a.s.family, b.s.family) || cmpStr(a.c.product, b.c.product));
  const ok = scored.filter((x) => !x.blocked);
  const best = ok[0];

  if (best && best.s.score >= T.match_min) {
    // a combo that lists the same product ("SharePoint" in ".NET Framework, SharePoint, Visual Studio") is no rival
    const rival = ok.find((x) => !sameProduct(x.s, best.s));
    const margin = best.s.score - (rival ? rival.s.score : 0);
    if (margin < T.margin_min) return none(CONF_ABSTAIN);
    // a vendor-named product the row may only be a neighbour of ("GitLab Runner", "Sudo for Windows"): unsure
    if (eponymousDoubt(ctx, best.c, list)) return none(CONF_ABSTAIN);
    const confidence = Math.min(0.95,
      0.55 + 0.25 * clamp01((best.s.score - T.match_min) / (1 - T.match_min)) + 0.15 * clamp01(margin / 0.3));
    return { pick: best.c, kevType: best.s.kevType, confidence: round(confidence, 2) };
  }
  const bestOk = best ? best.s.score : 0;
  if (bestOk >= T.no_match_max) return none(CONF_ABSTAIN);
  // a vague KEV entry that resembles the row ("Microsoft / Microsoft", "<vendor> / Multiple Products") may list the
  // row's product under that name: unsure, never a confident "no KEV product"
  if (scored.some((x) => x.s.vague && x.s.name >= T.lookalike_name_min)) return none(CONF_ABSTAIN);
  const near = scored.filter((x) => x.blocked && !x.s.vague && x.s.name >= T.lookalike_name_min);
  // the asset column contradicts the best name match (vCenter on a laptop): unsure, not "no match"
  if (near.some((x) => x.s.typeRel !== "conflict")) return none(CONF_ABSTAIN);
  return none(near.length ? CONF_LOOKALIKE : CONF_NO_MATCH);
}
