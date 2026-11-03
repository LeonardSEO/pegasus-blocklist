# Independent source architecture

The accepted plan uses external lists once as seeds, then produces its own observations and admitted indicators. Python standard-library modules keep the existing list formats, CI and GITHUB_TOKEN auto-merge chain.

- `bootstrap.py`: explicit one-time offline import of pinned source files. `sources/bootstrap.json` records hashes, source URLs/commits, normalized indicators and rejected records. It refuses to overwrite an existing bootstrap.
- `research.py`: persistent indicator/evidence/relationship/queue model, immutable observation IDs, detector qualification, admission, withdrawal and offline state validation.
- `probe.py`: root-only HTTP/TLS inspection with bounded DNS subprocesses, public-address checks, pinned sockets, no forwarded credentials and no infection-link navigation.
- `refresh.py`: read-only collection of CT, existing scans, current DNS, publication links and direct measurements. Pending work survives deadlines. A candidate cannot start unlimited recursive pivots.
- `publish.py`: trusted offline artifact merge and decision step. Incoming status/provenance fields cannot authorize publication. Existing evidence and historical provenance are retained.
- `build.py`: validated combined/discovered domain lists in eight formats plus separate standalone IP and IP:port lists.

The register separates `observed_at` (actual certificate/scan/measurement time) and `recorded_at` (when recorded). Bootstrap records have unknown first/last observation dates until actual evidence exists; source publication/import dates are not substituted. Raw response bodies, infection URL tokens, cookies and credentials are not collected. Certificate DER data and root-response hashes are public measurement evidence.

Detector policy is trusted versioned repository code/data. An enabled rule requires positive, negative and shadow examples referencing observations. TLS and HTTP evidence must refer to the same target/session; decisions use seven-day-fresh observations. Disabling a detector marks its own findings withdrawn; history is not deleted. Historical source indicators are independently retained.

The daily workflow has a read-only measurement job and a separate publisher with write permissions. The publisher checks out main, validates the JSON merge, evaluates policy, rebuilds output and opens an auto-merge PR. Measurement artifacts are data and are never executed. CI runs offline tests, state qualification/admission validation, reproducibility checks and resolver syntax checks.

Ruling: no current qualified Pegasus fingerprint is invented from historical domain lists. The production detector set remains empty until attributed evidence and shadow results justify enabling a rule. Controlled regression fixtures are not research positives.
