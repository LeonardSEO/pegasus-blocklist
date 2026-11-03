# Sources and attribution

Reviewed: 3 November 2026.

- [Amnesty International Pegasus indicators](https://github.com/AmnestyTech/investigations/tree/master/2021-07-18_nso): primary domain feed, also referenced by the [MVT indicator registry](https://github.com/mvt-project/mvt-indicators/blob/main/indicators.yaml). The domain file's latest upstream commit at initial review was `993479ef14c1f0c98f0ec6cc8cb5101173d35598`, dated 14 July 2022. It contains historical reported indicators, not evidence of current malicious ownership.
- [Forensic methodology, 18 July 2021](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/): explains historical infrastructure generations, certificate/DNS investigation and the role of forensic corroboration.
- [Inside Pegasus, 16 July 2026](https://securitylab.amnesty.org/latest/2026/07/inside-pegasus-the-evolution-of-the-worlds-most-notorious-spyware/): explains continuing NSO infrastructure management and customer-specific accounts/domains using disclosed internal documents. It is not a new comprehensive domain feed.
- [Amnesty inside-pegasus documents](https://github.com/AmnestyTech/inside-pegasus): research material, not automatically imported indicators.
- [The NSO Blacklist](https://github.com/0n1cOn3/The-NSO-Blacklist): comparison/reference only. Third-party hosts files and C2 IP:port lists are not blindly merged into DNS subscriptions.

Source SHA-256 and URL are recorded in `sources/provenance.json`. Changes to a trusted source are visible in update PRs and Git history. Research/discovery reports live in `candidates/latest.json`; reviewing those records does not automatically approve their candidates.

RSS monitoring tracks new relevant publication links. It does not reliably extract or attribute domains from prose, linked documents or screenshots. New sources require review before joining the trusted feed set. Government trade restrictions are not technical network indicators and are not used as DNS entries.
