"""Text reports for secret sharing."""

from __future__ import annotations

from .experiments import SubsetReport
from .shamir import Share, describe


def render_share(share: Share) -> str:
    return f"share x={share.x:<3} {share.payload.hex()}"


def render_shares(shares: list[Share]) -> str:
    lines = [f"{len(shares)} shares", "=" * 58]
    for share in shares:
        lines.append(render_share(share))
    lines.append("")
    lines.append("any k of these reconstruct the secret; any k-1 reveal nothing about it")
    return "\n".join(lines)


def render_subset_report(report: SubsetReport) -> str:
    lines = ["Subset verification", "=" * 58]
    lines.append(f"threshold            {report.threshold} of {report.shares}")
    lines.append(f"subsets tested       {report.subsets_tested:,}")
    lines.append(f"subsets reconstructed {report.subsets_ok:,}  ({report.success * 100:.1f}%)")
    lines.append("")
    return "\n".join(lines)


def render_size_table(rows: list[dict]) -> str:
    header = (
        f"{'secret':>7}{'k':>4}{'n':>4}{'share size':>12}{'total':>9}{'expansion':>11}"
        f"{'k-subsets':>11}"
    )
    lines = ["Share size against secret size", "=" * len(header), header]
    for row in rows:
        lines.append(
            f"{row['secret_bytes']:>7}{row['threshold']:>4}{row['shares']:>4}"
            f"{row['share_bytes']:>12}{row['total_share_bytes']:>9}"
            f"{row['expansion']:>10.2f}x{row['combinations']:>11,}"
        )
    lines.append("")
    lines.append("share size is one byte per secret byte plus the x coordinate")
    return "\n".join(lines)


def render_below_threshold(rows: list[tuple[int, int, int]]) -> str:
    lines = ["Combining fewer than k shares", "=" * 58]
    lines.append(f"{'k-1 shares':>11}{'trials':>9}{'distinct results':>18}")
    for holding, trials, distinct in rows:
        lines.append(f"{holding:>11}{trials:>9}{distinct:>18}")
    lines.append("")
    lines.append("every distinct result is a wrong secret, and the right one never appears")
    return "\n".join(lines)


def render_summary(secret: bytes, threshold: int, shares: int) -> str:
    info = describe(secret, threshold, shares)
    lines = ["Split summary", "=" * 58]
    lines.append(f"secret               {info['secret_bytes']} bytes")
    lines.append(f"threshold            {threshold} of {shares}")
    lines.append(f"share size           {info['share_bytes']} bytes")
    lines.append(f"total shares         {info['total_share_bytes']} bytes "
                 f"({info['expansion']:.2f}x the secret)")
    lines.append(f"k-subsets            {info['combinations']:,}")
    return "\n".join(lines)


def render_json(payload) -> str:
    import json

    return json.dumps(payload, indent=2, default=str)
