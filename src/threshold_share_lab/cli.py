"""Command line entry point for share-lab."""

from __future__ import annotations

import argparse
import secrets
import sys

from . import __version__
from .experiments import below_threshold_spread, size_table, verify_all_subsets
from .report import (
    render_below_threshold,
    render_json,
    render_shares,
    render_size_table,
    render_subset_report,
    render_summary,
)
from .shamir import Share, ShareError, combine, split


def _secret_from(args) -> bytes:
    if args.secret_hex:
        try:
            return bytes.fromhex(args.secret_hex)
        except ValueError as exc:
            raise ShareError(f"secret is not hex: {exc}") from exc
    if args.secret:
        return args.secret.encode("utf-8")
    return secrets.token_bytes(args.secret_bytes)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="share-lab",
        description="Split a secret k-of-n with Shamir over GF(256) and measure the trade-offs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("split", "split a secret and print the shares"),
        ("verify", "reconstruct from every k-subset"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--secret", default=None, help="literal secret (default: random)")
        cmd.add_argument("--secret-hex", default=None)
        cmd.add_argument("--secret-bytes", type=int, default=16)
        cmd.add_argument("--threshold", "-k", type=int, default=3)
        cmd.add_argument("--shares", "-n", type=int, default=5)
        cmd.add_argument("--format", choices=("text", "json"), default="text")

    combine_cmd = sub.add_parser("combine", help="reconstruct from shares given as x:hex")
    combine_cmd.add_argument("--share", action="append", required=True)

    sizes = sub.add_parser("sizes", help="share size and subset count against parameters")
    sizes.add_argument("--format", choices=("text", "json"), default="text")

    spread = sub.add_parser("below-threshold", help="what k-1 shares actually produce")
    spread.add_argument("--threshold", "-k", type=int, default=3)
    spread.add_argument("--shares", "-n", type=int, default=5)
    spread.add_argument("--trials", type=int, default=32)
    spread.add_argument("--secret-bytes", type=int, default=16)
    spread.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sizes":
        rows = size_table()
        if args.format == "json":
            print(render_json(rows))
        else:
            print(render_size_table(rows))
        return 0

    if args.command == "combine":
        shares = []
        try:
            for raw in args.share:
                coordinate, _, payload = raw.partition(":")
                shares.append(Share(x=int(coordinate), payload=bytes.fromhex(payload)))
            secret = combine(shares)
        except (ValueError, ShareError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(secret.decode("utf-8", errors="replace"))
        return 0

    if args.command == "below-threshold":
        try:
            secret = secrets.token_bytes(args.secret_bytes)
            distinct = below_threshold_spread(
                secret, threshold=args.threshold, shares=args.shares, trials=args.trials
            )
        except ShareError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        rows = [(args.threshold - 1, args.trials, distinct)]
        if args.format == "json":
            print(render_json({"holding": args.threshold - 1, "trials": args.trials,
                               "distinct": distinct}))
        else:
            print(render_below_threshold(rows))
        return 0

    try:
        secret = _secret_from(args)
        shares = split(secret, threshold=args.threshold, shares=args.shares)
    except ShareError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "split":
        if args.format == "json":
            print(render_json(
                {
                    "threshold": args.threshold,
                    "shares": len(shares),
                    "secret_bytes": len(secret),
                    "shares_hex": [share.as_dict() for share in shares],
                }
            ))
        else:
            print(render_summary(secret, args.threshold, args.shares))
            print()
            print(render_shares(shares))
        return 0

    report = verify_all_subsets(secret, threshold=args.threshold, shares=args.shares)
    if args.format == "json":
        print(render_json(report.as_dict()))
    else:
        print(render_subset_report(report))
        if report.subsets_ok != report.subsets_tested:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
