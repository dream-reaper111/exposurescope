# Security model

Import only passive data obtained under explicit authorization. The CLI cannot scan networks or contact imported hostnames. Scope checks use exact domain or subdomain matching; wildcard and out-of-scope names are skipped. Ownership is operator asserted, not automatically verified. JSON reports may reveal internal domain structure and should be handled as sensitive.

No live connector, API authentication, database, or audit log exists in the offline milestone. Source hashes and timestamps support traceability but do not prove a CT log inclusion event or asset ownership. The next service milestone must add source authorization and per-user review audit records.
