"""Offline passive DNS and CT-derived assertion import with explicit scope."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT = 100 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_RECORDS = 100000
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ScopeError(ValueError):
    pass


def host(value: str, scope: str | None = None) -> str:
    if not isinstance(value, str) or value.startswith("*."):
        raise ScopeError("wildcard or invalid host")
    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError("invalid IDNA host") from exc
    if len(normalized) > 253 or not all(HOST_LABEL.fullmatch(label) for label in normalized.split(".")):
        raise ScopeError("invalid DNS host")
    if scope and normalized != scope and not normalized.endswith("." + scope):
        raise ScopeError("host outside approved domain scope")
    return normalized


def _time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ScopeError("invalid observation timestamp") from exc
    if parsed.tzinfo is None:
        raise ScopeError("observation timestamp requires timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _lines(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ScopeError("input must be a regular file of at most 100 MiB")
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if number > MAX_RECORDS or len(raw) > MAX_LINE:
                raise ScopeError("record count or line length limit exceeded")
            if raw.strip():
                yield number, raw


def import_dns(path: Path, scope: str) -> tuple[list[dict], list[str]]:
    records = []
    issues = []
    for number, raw in _lines(path):
        try:
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ScopeError("not an object")
            name = host(row["name"], scope)
            kind = row["type"]
            if kind not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}:
                raise ScopeError("unsupported DNS record type")
            value = row["value"]
            if not isinstance(value, str) or len(value) > 4096:
                raise ScopeError("invalid DNS value")
            if kind in {"A", "AAAA"}:
                address = ipaddress.ip_address(value)
                if (kind == "A") != (address.version == 4):
                    raise ScopeError("address family mismatch")
                normalized_value = str(address)
                public_address = address.is_global
            elif kind in {"CNAME", "MX", "NS"}:
                normalized_value = host(value)
                public_address = None
            else:
                normalized_value = None
                public_address = None
            source = row["source"]
            if not isinstance(source, str) or not 1 <= len(source) <= 256:
                raise ScopeError("invalid source")
            records.append({"name": name, "type": kind, "value": normalized_value,
                            "value_sha256": hashlib.sha256(value.encode()).hexdigest() if kind == "TXT" else None,
                            "public_address_observed": public_address,
                            "observed_at": _time(row["observed_at"]), "source": source,
                            "record_sha256": hashlib.sha256(raw).hexdigest(),
                            "reference": f"{path.name}:line:{number}"})
        except (ValueError, KeyError, TypeError):
            issues.append(f"{path.name}:line:{number}: invalid or out-of-scope DNS assertion")
    return records, issues


def import_ct(path: Path, scope: str) -> tuple[list[dict], list[str]]:
    records = []
    issues = []
    for number, raw in _lines(path):
        try:
            row = json.loads(raw)
            if not isinstance(row, dict) or not isinstance(row.get("dns_names"), list):
                raise ScopeError("invalid CT assertion")
            fingerprint = row["certificate_sha256"]
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
                raise ScopeError("invalid certificate fingerprint")
            source = row["source"]
            if not isinstance(source, str) or not 1 <= len(source) <= 256:
                raise ScopeError("invalid source")
            observed = _time(row["observed_at"])
            for name in row["dns_names"][:100]:
                try:
                    normalized = host(name, scope)
                except ScopeError:
                    issues.append(f"{path.name}:line:{number}: wildcard or out-of-scope SAN skipped")
                    continue
                records.append({"name": normalized, "certificate_sha256": fingerprint.lower(),
                                "observed_at": observed, "source": source,
                                "record_sha256": hashlib.sha256(raw).hexdigest(),
                                "reference": f"{path.name}:line:{number}",
                                "verification": "source assertion; CT inclusion proof not checked"})
            if len(row["dns_names"]) > 100:
                issues.append(f"{path.name}:line:{number}: SAN list truncated at 100")
        except (ValueError, KeyError, TypeError):
            issues.append(f"{path.name}:line:{number}: invalid CT assertion")
    return records, issues


def ownership(path: Path | None, scope: str) -> dict[str, str]:
    if path is None:
        return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ScopeError("ownership file must be a regular JSON file under 1 MiB")
    try:
        data = json.loads(path.read_bytes())
    except ValueError as exc:
        raise ScopeError("invalid ownership JSON") from exc
    if not isinstance(data, dict):
        raise ScopeError("ownership data must be a mapping")
    result = {}
    for name, owner in data.items():
        if not isinstance(owner, str) or not 1 <= len(owner) <= 128:
            raise ScopeError("invalid owner label")
        result[host(name, scope)] = owner
    return result


def build_report(scope: str, dns_paths: list[Path], ct_paths: list[Path],
                 owners: dict[str, str] | None = None, previous: dict | None = None) -> dict:
    scope = host(scope)
    if not dns_paths and not ct_paths:
        raise ScopeError("at least one authorized import is required")
    dns_records = []
    ct_records = []
    issues = []
    for path in dns_paths:
        found, notes = import_dns(path, scope)
        dns_records.extend(found)
        issues.extend(notes)
    for path in ct_paths:
        found, notes = import_ct(path, scope)
        ct_records.extend(found)
        issues.extend(notes)
    if len(dns_records) + len(ct_records) > MAX_RECORDS:
        raise ScopeError("aggregate record limit exceeded")
    assets = {}
    relations = []
    for row in dns_records + ct_records:
        name = row["name"]
        asset = assets.setdefault(name, {"name": name, "sources": set(), "first_observed": row["observed_at"],
                                         "last_observed": row["observed_at"], "public_address_observed": False})
        asset["sources"].add(row["source"])
        asset["first_observed"] = min(asset["first_observed"], row["observed_at"])
        asset["last_observed"] = max(asset["last_observed"], row["observed_at"])
        asset["public_address_observed"] |= bool(row.get("public_address_observed"))
        target = row.get("value") or row.get("certificate_sha256")
        if target:
            relations.append({"source": name, "target": target, "type": row.get("type", "certificate"),
                              "record_sha256": row["record_sha256"]})
    for asset in assets.values():
        asset["sources"] = sorted(asset["sources"])
        asset["owner"] = (owners or {}).get(asset["name"])
        asset["ownership_status"] = "operator_asserted" if asset["owner"] else "unreviewed"
    prior_names = set()
    if previous is not None:
        if not isinstance(previous, dict) or previous.get("schema_version") != 1 or previous.get("scope") != scope:
            raise ScopeError("previous inventory schema or scope mismatch")
        prior_assets = previous.get("assets")
        if not isinstance(prior_assets, list) or len(prior_assets) > MAX_RECORDS:
            raise ScopeError("previous asset inventory invalid or too large")
        prior_names = {item["name"] for item in prior_assets if isinstance(item, dict) and isinstance(item.get("name"), str)}
    current_names = set(assets)
    return {"schema_version": 1, "scope": scope, "assets": [assets[name] for name in sorted(assets)],
            "relationships": relations, "dns_records": dns_records, "ct_assertions": ct_records,
            "changes": {"newly_observed": sorted(current_names - prior_names) if previous else [],
                        "not_observed_in_current_import": sorted(prior_names - current_names) if previous else []},
            "issues": issues, "network_requests": 0,
            "interpretation": "passive source assertions; public IP does not prove service exposure or asset ownership"}
