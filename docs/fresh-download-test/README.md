# Fresh-download test on a second computer (27 Oct 2026)

A team member (Mohd Amir Suhel) downloaded this repository as a ZIP on his own computer, set up his own Zetaris, Nightshift and NVIDIA key, and followed the README, as a judge would. These are two of his runs, saved from the app's report page and not edited:

| File | Run | Result |
|---|---|---|
| [`report-demo-2.html`](report-demo-2.html) | live (Zetaris + Nightshift), `input_examples/example_1.json`, 27 Oct, 20:06 UK | status success, 112.6 s, 7 / 0 / 4 / 1 (patch now / this cycle / monitor / ask owner); 10 model calls, each with a Nightshift receipt |
| [`report-demo-offline-1.html`](report-demo-offline-1.html) | sample mode, offline (no Zetaris, no Nightshift, no keys), 27 Oct, 20:24 UK | status success, 165 ms, 3 / 0 / 3 / 6; 0 model calls; the report shows the SAMPLE MODE banner |

Earlier attempts on that computer reached Nightshift, but NVIDIA refused the provider key saved there (`HTTP 502 provider_auth_failed`). Those runs still finished, marked `partial`, and named the error on every failed call. With a new NVIDIA key in Nightshift (Setup → Providers), the live run above succeeded.
