# Pegasus blocklist

Published Pegasus / NSO domain indicators with daily source monitoring, passive discovery and validated automatic publication.

**The initial source is historical Amnesty International data, not a current inventory of active Pegasus servers. A build date is not a threat-observation date.** DNS blocking cannot prevent every zero-click exploit or establish that a device is clean.

<!-- LISTS:START -->

**1438 unique domains**, **1438 after wildcard compression**.

### Pegasus Published Indicators

Published Pegasus / NSO domain indicators; includes historical infrastructure

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

<!-- LISTS:END -->

Use the Adblock format for compatible AdGuard Home/uBlock Origin subscriptions, or Domains for Pi-hole. Hosts matches exact names. Wildcard formats require a client that matches descendants. Do not import IP:port pairs into a DNS list.

## What updates automatically

Every day at 06:47 UTC, GitHub Actions:

1. Fetches Amnesty's published domain feed, validates every entry and records its SHA-256. Changes to this explicitly trusted feed update `sources/amnesty-pegasus.txt` automatically. Invalid/empty feeds fail; temporary source outages preserve the last snapshot and produce a partial report.
2. Reads Amnesty Security Lab and Citizen Lab RSS feeds for Pegasus/NSO publications and stores new links for review. New reports are not automatically interpreted as new malicious domains.
3. Rotates through up to 24 known domains per day, querying public Certificate Transparency records, existing urlscan results and DNS-over-HTTPS. SAN names on certificates containing a known seed may reveal other domains. Shared addresses, nameservers or certificates remain leads, not proof of NSO ownership.
4. Records evidence, errors, selected seeds, query limits and UTC observation time in `candidates/latest.json`. The report distinguishes service failures from skipped/unqueried coverage.
5. Rebuilds eight formats, opens a PR targeting `main`, dispatches CI and auto-merges after the `CI validated` status succeeds. Dependabot checks pinned Actions daily; validated same-repository PRs also auto-merge. Drafts and fork PRs require maintainer handling.

Discovery candidates never enter a subscription automatically. After reviewing evidence and current ownership, add a justified domain to `candidates/approved.txt`. Detection of previously unpublished infrastructure is a research lead, not a promise of independently verified Pegasus attribution.

## Sources and freshness

The monitored Amnesty feed currently lives in the `2021-07-18_nso` directory. Its directory name and the July 2026 research report are different things: fetching this feed today does not turn it into a 2026 domain inventory. See [sources and attribution](docs/SOURCES.md) and the stored upstream digest in `sources/provenance.json`.

The [July 2026 Amnesty analysis](https://securitylab.amnesty.org/latest/2026/07/inside-pegasus-the-evolution-of-the-worlds-most-notorious-spyware/) explains NSO's continuing infrastructure operations; it does not publish a universal current server fingerprint. No old TLS fingerprint is treated as a reliable present-day Pegasus detector.

## Development

Python 3.10+, standard library only:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/refresh.py --max-seconds 600
python3 scripts/build.py
python3 scripts/build.py --check
```

`refresh.py` returns 3 for documented partial public-service results; argument and unexpected script errors retain separate nonzero exit codes. It never fetches suspect web endpoints or submits new urlscan scans. Public-service calls reveal the queried historical domains to those services. No API key or extra access token is required.

Daily seed selection rotates deterministically. With N published domains, a rotation takes approximately ceil(N/24) days; timeouts and API first-page limits can reduce actual coverage. A historical domain may now belong to someone else. The exact allowlist protects known shared-platform roots but does not replace domain review.

## Automation settings

Allow Actions to create PRs, enable squash auto-merge and require the `CI validated` status on `main`. Dispatch CI explicitly for bot-created branches: GitHub job checks from dispatch do not attach to PRs, so a separate job publishes a commit status after both Python jobs succeed. The privileged publishing/merge jobs never check out PR code. Errors and merge conflicts can block automatic updates.

## License

Project code: MIT. Original project compilation/additions: CC BY-NC-SA 4.0. Third-party facts and research retain their original attribution and applicable terms; this project does not relicense Amnesty's reports or claim affiliation. See [LICENSE](LICENSE).
