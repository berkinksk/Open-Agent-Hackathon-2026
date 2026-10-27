import { test } from "node:test";
import assert from "node:assert/strict";
import type { NvdRange } from "../src/contracts.ts";
import {
  compareToBound, compareVersions, fixedVersion, hasVersion, inRange, isAffected, isAllVersions, namesEdition, parseCpe, rangesForProduct,
} from "../src/resolve/versions.ts";

const R = (criteria: string, b: Partial<NvdRange> = {}, vulnerable = true): NvdRange => ({ cve_id: "CVE-2000-0001", criteria, vulnerable, ...b });
const LOG4J = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*";

test("compareVersions: numeric parts compare as numbers", () => {
  assert.equal(compareVersions("2.14.1", "2.15.0"), -1);
  assert.equal(compareVersions("2.4.49", "2.4.50"), -1);
  assert.equal(compareVersions("10.0", "9.9"), 1);
  assert.equal(compareVersions("7.2.4", "7.2.4"), 0);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
  assert.equal(compareVersions("v2.14.1", "2.14.1"), 0);
  assert.equal(compareVersions("2.14.1 (bundled in ERP-Portal WAR)", "2.14.1"), 0);
});

test("compareVersions: pre-releases sort before the release, letter suffixes after", () => {
  assert.equal(compareVersions("2.0-beta9", "2.0"), -1);
  assert.equal(compareVersions("2.0-beta9", "2.0-rc1"), -1);
  assert.equal(compareVersions("2.0-rc2", "2.0-rc1"), 1);
  assert.equal(compareVersions("3.12.0a1", "3.12.0"), -1);
  assert.equal(compareVersions("1.0.2k", "1.0.2"), 1);
  assert.equal(compareVersions("1.0.2k", "1.0.3"), -1);
  assert.equal(compareVersions("8.9p1", "8.9"), 1);
});

test("compareVersions: Citrix build numbers and Exchange cumulative updates", () => {
  assert.equal(compareVersions("13.1-48.47", "13.1-49.13"), -1);
  assert.equal(compareVersions("13.1-49.13", "13.1"), 1);
  assert.equal(compareVersions("2019 CU12", "2019-cumulative_update_12"), 0);
  assert.equal(compareVersions("2019 CU12", "2019 CU13"), -1);
});

test("compareToBound: a vaguer version than the bound is unknown, not a guess", () => {
  assert.equal(compareToBound("2.4", "2.4.49"), "unknown");
  assert.equal(compareToBound("13.1", "13.1-49.13"), "unknown");
  assert.equal(compareToBound("2019", "2019-cu12"), "unknown");
  assert.equal(compareToBound("1.0", "1.0.0"), 0);          // trailing zeros are equal
  assert.equal(compareToBound("2.0", "2.0-beta9"), 1);      // the release is above its pre-release
  assert.equal(compareToBound("2.14", "2.15.0"), -1);       // differs before the bound ends: decidable
});

test("isAffected: including/excluding boundaries", () => {
  const range = R(LOG4J, { version_start_including: "2.13.0", version_end_excluding: "2.15.0" });
  assert.equal(isAffected("2.13.0", [range]), true);   // start including: equal is in
  assert.equal(isAffected("2.14.1", [range]), true);
  assert.equal(isAffected("2.15.0", [range]), false);  // end excluding: equal is out
  assert.equal(isAffected("2.12.9", [range]), false);

  const excl = R(LOG4J, { version_start_excluding: "2.0", version_end_including: "2.3" });
  assert.equal(isAffected("2.0", [excl]), false);      // start excluding: equal is out
  assert.equal(isAffected("2.0.1", [excl]), true);
  assert.equal(isAffected("2.3", [excl]), true);       // end including: equal is in
  assert.equal(isAffected("2.3.1", [excl]), false);
});

test("isAffected: several ranges are OR-ed; non-vulnerable entries are ignored", () => {
  const ranges = [
    R(LOG4J, { version_start_including: "2.0.1", version_end_excluding: "2.3.1" }),
    R(LOG4J, { version_start_including: "2.4", version_end_excluding: "2.12.2" }),
    R(LOG4J, { version_start_including: "2.13.0", version_end_excluding: "2.15.0" }),
    R("cpe:2.3:o:example:platform:*:*:*:*:*:*:*:*", {}, false),
  ];
  assert.equal(isAffected("2.11.0", ranges), true);
  assert.equal(isAffected("2.12.2", ranges), false);
  assert.equal(isAffected("2.17.1", ranges), false);
});

test("isAffected: unknown when the version or the ranges cannot decide", () => {
  const range = R("cpe:2.3:o:citrix:netscaler_application_delivery_controller_firmware:*:*:*:*:*:*:*:*", { version_start_including: "13.1", version_end_excluding: "13.1-49.13" });
  assert.equal(isAffected("13.1-48.47", [range]), true);
  assert.equal(isAffected("13.1-49.13", [range]), false);
  assert.equal(isAffected("13.1", [range]), "unknown");     // which 13.1 build?
  assert.equal(isAffected(null, [range]), "unknown");
  assert.equal(isAffected("", [range]), "unknown");
  assert.equal(isAffected("latest", [range]), "unknown");   // no digits
  assert.equal(isAffected("2.14.1", []), "unknown");        // NVD has no configurations yet
  assert.equal(isAffected("2.14.1", [R(LOG4J, {}, false)]), "unknown");
});

test("isAffected: exact-version CPEs (no bounds) and wildcards", () => {
  const beta9 = R("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*");
  assert.equal(isAffected("2.0-beta9", [beta9]), true);
  assert.equal(isAffected("2.0", [beta9]), false);
  const cu12 = R("cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_12:*:*:*:*:*:*");
  assert.equal(isAffected("2019 CU12", [cu12]), true);
  assert.equal(isAffected("2019 CU14", [cu12]), false);
  assert.equal(isAffected("2019", [cu12]), "unknown");   // which CU?
  const anyUpdate = R("cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*");
  assert.equal(isAffected("2019 CU12", [anyUpdate]), true);
  assert.equal(isAffected("2016 CU23", [anyUpdate]), false);
  const all = R("cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*");
  assert.equal(isAllVersions(all), true);
  assert.equal(isAffected(null, [all]), true);            // every version: no version needed
  assert.equal(isAffected("1.0", [R("cpe:2.3:a:example:widget:-:*:*:*:*:*:*:*")]), "unknown");
});

test("inRange: a pre-release lower bound admits the release line", () => {
  const r = R(LOG4J, { version_start_including: "2.0-beta9", version_end_excluding: "2.3.1" });
  assert.equal(inRange("2.0", r), true);
  assert.equal(inRange("2.0-beta8", r), false);
  assert.equal(inRange("2.0-rc1", r), true);
});

test("parseCpe handles escapes and rejects other strings", () => {
  assert.deepEqual(parseCpe("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"), { part: "a", vendor: "apache", product: "log4j", version: "2.0", update: "beta9" });
  assert.equal(parseCpe("cpe:2.3:a:vendor:prod\\:uct:1.0:*:*:*:*:*:*:*")?.product, "prod:uct");
  assert.equal(parseCpe("cpe:/a:apache:log4j:2.0"), null);
  assert.equal(parseCpe(""), null);
});

test("rangesForProduct keeps the KEV product's CPEs out of a multi-vendor CVE", () => {
  const ranges = [
    R(LOG4J, { version_start_including: "2.13.0", version_end_excluding: "2.15.0" }),
    R("cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*", { version_start_including: "2.4", version_end_excluding: "3.1" }),
  ];
  const mine = rangesForProduct(ranges, "Apache", "Log4j2");
  assert.equal(mine.length, 1);
  assert.match(mine[0].criteria, /apache:log4j/);
  // without the filter, the Cisco range would claim a log4j version "2.4.1" is affected
  assert.equal(isAffected("2.4.1", ranges), true);
  assert.equal(isAffected("2.4.1", mine), false);
  assert.equal(rangesForProduct(ranges, "Fortinet", "FortiOS").length, 0);
  const pan = [R("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", { version_end_excluding: "10.2.9" })];
  assert.equal(rangesForProduct(pan, "Palo Alto Networks", "PAN-OS").length, 1);
});

test("fixedVersion and hasVersion", () => {
  const ranges = [
    R(LOG4J, { version_start_including: "2.13.0", version_end_excluding: "2.15.0" }),
    R(LOG4J, { version_start_including: "2.4", version_end_excluding: "2.12.2" }),
  ];
  assert.equal(fixedVersion("2.14.1", ranges), "2.15.0");
  assert.equal(fixedVersion(null, ranges), "2.12.2");
  assert.equal(hasVersion("7.0.9"), true);
  assert.equal(hasVersion("n/a"), false);
  assert.equal(hasVersion(null), false);
});

test("an edition label is never compared with build-number bounds (Windows 23H2, Server 2019)", () => {
  // NVD bounds Windows by build per edition; "23H2" read as a number (23 > 10) would wrongly say "not affected"
  const win11 = R("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*", { version_end_excluding: "10.0.22631.4317" });
  const win10 = R("cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*", { version_end_excluding: "10.0.19045.5011" });
  const srv = R("cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", { version_end_excluding: "10.0.17763.6414" });
  assert.equal(namesEdition("23H2", win11.criteria), true);
  assert.equal(namesEdition("2019", srv.criteria), true);
  assert.equal(namesEdition("2.4.49", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"), false);
  assert.equal(namesEdition("2019 CU12", "cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_12:*:*:*:*:*:*"), false);
  assert.equal(inRange("23H2", win11), "unknown");
  assert.equal(inRange("2019", srv), "unknown");
  assert.equal(isAffected("23H2", [win11, win10, srv]), "unknown"); // never false: the build decides
  // a real build is still compared
  assert.equal(isAffected("10.0.22631.4000", [win11]), true);
  assert.equal(isAffected("10.0.22631.4317", [win11]), false);
});
