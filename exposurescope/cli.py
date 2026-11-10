from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import ScopeError, build_report, ownership


def main() -> None:
    parser = argparse.ArgumentParser(prog="exposurescope")
    parser.add_argument("--scope", required=True, help="authorized parent DNS domain")
    parser.add_argument("--dns", action="append", type=Path, default=[])
    parser.add_argument("--ct", action="append", type=Path, default=[])
    parser.add_argument("--owners", type=Path)
    parser.add_argument("--previous", type=Path, help="previous JSON report for comparison")
    args = parser.parse_args()
    try:
        if args.previous and (args.previous.is_symlink() or not args.previous.is_file()
                              or args.previous.stat().st_size > 16 * 1024 * 1024):
            raise ScopeError("previous report must be a regular JSON file under 16 MiB")
        prior = json.loads(args.previous.read_bytes()) if args.previous else None
        report = build_report(args.scope, args.dns, args.ct, ownership(args.owners, args.scope), prior)
    except (ScopeError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
