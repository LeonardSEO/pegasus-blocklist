# Design

The user selected a separate Pegasus repository instead of extending AdFection. Reuse the existing Python standard-library build, eight output formats, resolver CI and tested GITHUB_TOKEN PR/merge chain. No framework, runtime dependency, server, account secret or active Internet scan is needed.

`refresh.py` owns validated source synchronization, public publication monitoring and bounded passive discovery. `build.py` owns parsing, exact allowlisting, deduplication, wildcard compression and reproducible output validation. Only `sources/*.txt` and reviewed `candidates/approved.txt` affect subscriptions. Discovery JSON never becomes build input.

Automatically copying third-party blocklists would be smaller but would lose attribution control. Automatically classifying unseen domains as Pegasus from co-hosting/SAN overlap would not provide enough evidence. The chosen approach automates finding and publishing evidence while reserving attribution of new infrastructure for review.

Verification: offline tests exercise source validation/preservation, external SAN discovery, publisher exclusion, date rotation, partial errors and build/format coverage. Live Actions must demonstrate update PR creation, dispatched CI, required status publication and automatic merge.
