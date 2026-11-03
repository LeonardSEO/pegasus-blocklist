# Pegasus blocklist and independent research

A frozen published/community starting dataset plus our own persistent research source. Daily GitHub Actions collect observations, perform bounded root-only measurements and publish validated evidence directly to main. External blocklists are **not** downloaded during daily runs.

**Historical attribution is not current malicious ownership. DNS blocking cannot prevent all spyware infections. No current Pegasus detector has passed qualification yet: independent evidence collection is active, automatic admission of own findings is disabled.**

## Shared Free API access

Both projects use one credential-isolated urlscan/Censys coordinator in Adfection. Add `URLSCAN_API_KEY` and `CENSYS_PAT` there once. Shared reservations prevent manual reruns or the second repository from duplicating budgets; Censys uses Free asset lookups only. The provider job runs at 05:47 UTC, before daily research. No new scans are submitted.

See [Free API setup, limits and diagnosis](docs/FREE-API.md). The normal measurement jobs remain secret-free and use our sanitized public observations.

## Independent research

Daily Actions produce this project's own evidence dataset. Community and published indicators remain a frozen starting set; daily runs do not download other blocklists. The regular subscriptions contain historical bootstrap indicators and any own findings admitted by qualified detectors. Their presence does not imply every historical host is currently malicious.

Candidate observations and supporting evidence remain in [research/registry.json](research/registry.json). Candidates receive bounded DNS/TLS/HTTP measurements and enter a blocklist only after the configured admission requirements are met. The removed optional candidate-list subscriptions are no longer published.

A read-only collector and separate publisher validate evidence, tests, generated lists and resolver syntax, then push updates directly to `main`. The shared Free API integration and daily schedules continue as described above and in [architecture](docs/ARCHITECTURE.md).

<!-- LISTS:START -->

**5087 unique domains**, **5000 after wildcard compression**.

### Pegasus Combined

Frozen published/community seed data and qualified independent findings; includes historical infrastructure

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/adblock/pegasus.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/dnsmasq/pegasus.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/pegasus-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/wildcard/pegasus-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/wildcard/pegasus.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/domains/pegasus.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/hosts/pegasus.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/rpz/pegasus.txt) |
| Unbound | Unbound local-zone configuration | [unbound/pegasus.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/unbound/pegasus.txt) |

### Pegasus Independently Discovered

Own findings supported by qualified versioned detectors; empty until qualification succeeds

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/adblock/pegasus-discovered.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/dnsmasq/pegasus-discovered.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/pegasus-discovered-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/wildcard/pegasus-discovered-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/wildcard/pegasus-discovered.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/domains/pegasus-discovered.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/hosts/pegasus-discovered.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/rpz/pegasus-discovered.txt) |
| Unbound | Unbound local-zone configuration | [unbound/pegasus-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/unbound/pegasus-discovered.txt) |

<!-- LISTS:END -->

Additional data, **not DNS subscriptions**:

- [IP addresses](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/ips/pegasus.txt): standalone IP records only.
- [IP:port endpoints](https://raw.githubusercontent.com/LeonardSEO/pegasus-blocklist/main/lists/endpoints/pegasus.txt): does not imply blocking every port on those addresses.
- [Persistent evidence register](research/registry.json), [frozen source manifest](sources/bootstrap.json), [latest run report](candidates/latest.json).

Use Adblock with compatible AdGuard Home/uBlock Origin clients, Domains with Pi-hole, or the matching resolver format. Hosts blocks exact names; wildcard-aware formats include descendants. `pegasus-discovered` is intentionally available and empty until a detector qualifies. The combined `pegasus` URLs retain their existing locations and now include the cleaned community bootstrap.

## Independent daily research

At **06:47 UTC**, or on manual dispatch, a read-only job runs for at most 600 seconds of research work. It prioritizes unprocessed candidates and rotates through 24 historical/admitted seed domains. A persisted task queue resumes unfinished work. Candidate domains get DNS and root probes; only historical or admitted domains can drive CT/seed searches. Qualified detector-specific urlscan archive queries can discover new standalone domains independently of known roots.

Evidence includes CT/SAN names, A/AAAA/CNAME/NS observations, existing urlscan page/IP/time observations, and direct DNS/TLS/HTTP root measurements. Certificate issuance, scan time, collection time and first/last observation are distinct. Identical observations keep their original record; a shared IP, ASN, NS or certificate alone never authorizes a block.

Direct probes use ports 80/443 and explicit ports from scan observations no older than seven days. They pin a checked public IP, reject mixed public/private DNS answers, bound reads to 64 KiB, and follow at most three root-only redirects. They do not visit infection paths, query-token links, login pages by path, private networks or cloud metadata services. TLS certificates are inspected as untrusted evidence, without claiming CA authentication. Response bodies and cookies are not stored; fingerprints and public certificates are.

Expected source/probe failures produce partial reports and preserve existing evidence/indicators. Interrupted tasks remain queued. Public APIs and the ten-minute budget limit coverage; a daily run is not an exhaustive Internet scan. Public providers see the queried domains. No exploits, logins, browser execution or port sweeps are performed.

## Qualification and publication

`research/detectors.json` starts with **no enabled rules**. The engine supports explicit AND-matches combining TLS and HTTP fingerprints (optionally DNS nameservers), an attributed positive set, five measured negative classes (CDN, shared hosting, parking, re-registration, generic server) and distinct shadow evidence. Synthetic tests prove engine behavior, not real Pegasus detection.

Every admitted finding records the detector ID/version, supporting evidence and decision time. Measurements supporting a decision must be fresh (seven days), belong to one target and TLS/HTTP session, and pass the rule. Duplicating evidence does not add a channel. Disabling or replacing a detector withdraws its findings while preserving the bootstrap and all historical evidence. Qualification is a research judgement captured once per detector, not human approval of every match.

The privileged publication job checks out trusted `main`, downloads only this run's JSON artifact, merges new observations without trusting artifact admission/status fields, evaluates rules offline and validates every admission. It then rebuilds lists, runs offline tests and resolver validation, and pushes directly to `main`. CI is explicitly dispatched after publication. The measurement job has no repository write token or secrets, and checkout does not persist credentials.

The source import is frozen. Changes to the historical startset are explicit reviewed migrations, not an ongoing external-feed dependency. Existing `candidates/approved.txt` cannot bypass the evidence register for new own findings.

## Development

Python 3.10+ and its standard library; no extra runtime package or API credential:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/refresh.py --max-seconds 600
python3 scripts/publish.py
python3 scripts/publish.py --check
python3 scripts/build.py
python3 scripts/build.py --check
```

To merge a downloaded measurement artifact, use `publish.py --measurements DIRECTORY`; the directory contains `research/registry.json` and `candidates/latest.json`. `refresh.py` returns 3 for partial research; unexpected errors fail publication. `build.py --check` compares generated bytes at the published version timestamp.

See [sources](docs/SOURCES.md), [architecture](docs/ARCHITECTURE.md), [detector research](docs/DETECTOR-RESEARCH.md) and [LICENSE](LICENSE). Third-party source facts retain attribution and applicable rights. This project is not affiliated with Amnesty, Citizen Lab or the community-list authors.
