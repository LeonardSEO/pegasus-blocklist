# Frozen bootstrap and own source

Imported once on 3 November 2026. The authoritative manifest is `sources/bootstrap.json`: pinned Git commits/URLs, original byte SHA-256, source dates, normalized membership and rejected records. Scheduled research never re-downloads these lists.

Bootstrap inputs:

- [Amnesty Pegasus domains](https://github.com/AmnestyTech/investigations/tree/master/2021-07-18_nso), last changed 14 July 2022 at review: 1,438 published historical names. The directory date and a new publication/build date are not an indicator's last-seen date.
- [0n1cOn3/The-NSO-Blacklist](https://github.com/0n1cOn3/The-NSO-Blacklist), `hosts.txt` and `C2-hosts.txt`: community claims including historical data, additional domain names, standalone IPs and endpoint pairs.
- [Red-Laboratory/NSO-hosts](https://github.com/Red-Laboratory/NSO-hosts), `NSO-hosts.txt`.
- [jjjxu/NSO_Pegasus_Blocklist](https://github.com/jjjxu/NSO_Pegasus_Blocklist), `Pegasus-Hosts-Formatted.txt`.

The exact shared root `cloudfront.net` and malformed `iusacell-movil. com.mx` records are excluded; a broken record is never split into a `com.mx` block. Explicit tenant hosts remain eligible. Duplicates retain every source ID. Seven standalone IPs are annotated NoviSpy using [Amnesty's separate NoviSpy data](https://github.com/AmnestyTech/investigations/blob/master/2024-12-16_serbia_novispy/novispy.stix2), not silently relabelled as Pegasus. A community source claim is not independent verification of current ownership/activity.

`research/registry.json` is our own persistent source: candidates, observations, relationships, admissions, withdrawals and pending work. The prior discovery report's certificate observations are migrated with their original issuance dates; they do not become fresh Pegasus detections.

Research basis: [Amnesty 2021 methodology](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/), [Amnesty July 2026 architecture analysis](https://securitylab.amnesty.org/latest/2026/07/inside-pegasus-the-evolution-of-the-worlds-most-notorious-spyware/) and [Citizen Lab Hide and Seek](https://citizenlab.ca/research/hide-and-seek-tracking-nso-groups-pegasus-spyware-to-operations-in-45-countries/). These publications inform research, not automatic wholesale domain extraction. News-site references, decoy destinations, fingerprints from old generations and sanctions lists are not automatically network indicators.

Dataset facts retain source attribution and applicable third-party rights. The project's license covers its own compilation/additions and code, and does not relicense research publications or imply author endorsement. Red-Laboratory and jjjxu publish their project modifications under MIT; their notices remain available at the pinned source references.

## Independent-source migration (3 November 2026)

`sources/bootstrap.json` pins the initial source membership and hashes. Daily collection never downloads external blocklists. The register is now the publication source; old source/approved files remain historical records. Candidate evidence remains in the research register. Publication of own findings uses qualified detectors under the rules in `docs/ARCHITECTURE.md`. Historical manual-review instructions above describe the original bootstrap.
