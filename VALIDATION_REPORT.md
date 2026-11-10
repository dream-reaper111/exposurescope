# ExposureScope validation report

Date: 2026-11-09. Tests used only isolated `.invalid` domains and documentation-range addresses; no live collection occurred.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed |
| `python3 -m unittest discover -s tests -v` | 4 passed, 0 failed, 0 skipped |
| Scope validation, DNS/CT-derived import, TXT omission, ownership, comparison | Unit tested |
| Live passive DNS or CT source, inclusion proof, service reachability | Not verified or not implemented |
| Ruff/pytest | Unavailable in documented environment |

Next validation requires authorized exports with known provenance and a review of false asset associations. No live attack surface assessment is claimed.
