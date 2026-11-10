# ExposureScope

ExposureScope's first milestone builds a passive, offline inventory from authorized DNS and certificate-transparency-derived exports. It enforces an explicit parent-domain scope, normalizes hosts and A/AAAA/CNAME/MX/NS/TXT assertions, deduplicates assets, records source and observation timestamps, compares inventory snapshots, and produces a JSON relationship report. It makes **zero network requests** and does not scan services.

## Input schema

The importer uses a documented project-owned JSON Lines schema. Each DNS line is an object with `name`, `type`, `value`, `observed_at` (timezone-aware ISO 8601), and `source`. Each CT-derived line has `dns_names` (array), `certificate_sha256` (64 hex characters), `observed_at`, and `source`. CT inclusion proofs are **not** verified; these are source assertions. TXT values are not returned, only a SHA-256 reference. Operator-supplied ownership is a JSON mapping from fully qualified host to owner label, explicitly marked `operator_asserted`.

```bash
PYTHONPATH=. python3.12 -m exposurescope.cli --scope example.org --dns /path/to/authorized-dns.jsonl --ct /path/to/authorized-ct.jsonl --owners /path/to/owners.json > inventory-report.json
PYTHONPATH=. python3.12 -m exposurescope.cli --scope example.org --dns /path/to/current-dns.jsonl --previous /path/to/inventory-report.json > comparison.json
python3.12 -m unittest discover -s tests -v
```

The `changes` section reports newly observed and not observed in the current import. Absence is not evidence that an asset was removed. `public_address_observed` means an A/AAAA assertion points to a globally routable IP according to Python's address classification; it does not prove a service is reachable or owned by the organization. Source file line references and record hashes preserve provenance.

## Status

Offline imports, scope enforcement, deduplication, comparison, ownership labeling, and isolated tests work. No live passive DNS/CT connector, inclusion-proof validation, public service validation, vulnerability association, API, database, or dashboard is implemented. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). Next: validate against authorized export formats, add source-specific adapters and proof metadata, then an authenticated review workflow.
