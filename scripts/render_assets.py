"""Regenerate README assets from real runs.

Usage:  python scripts/render_assets.py
Writes: docs/results.json, docs/images/lab.png,
        docs/images/subsets.png, docs/images/expansion.png
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threshold_share_lab.experiments import (  # noqa: E402
    below_threshold_spread,
    size_table,
    verify_all_subsets,
)
from threshold_share_lab.report import (  # noqa: E402
    render_below_threshold,
    render_shares,
    render_size_table,
    render_subset_report,
    render_summary,
)
from threshold_share_lab.shamir import split  # noqa: E402

BG = "#0d1117"
CHROME = "#161b22"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#79c0ff"
SECRET = b"vault-unseal-token"
CONFIGS = ((2, 3), (3, 5), (5, 9))


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("consola.ttf", "courier.ttf", "DejaVuSansMono.ttf"):
        candidate = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / name
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def render_terminal(text: str, out_path: Path, title: str) -> None:
    font = load_font(15)
    lines = text.expandtabs(4).splitlines() or [""]
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    char_width = probe.textlength("M", font=font)
    line_height = 21
    pad = 24
    width = int(max(len(line) for line in lines) * char_width) + pad * 2
    height = pad * 2 + len(lines) * line_height + 44
    image = Image.new("RGB", (max(width, 780), height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, image.width, 34], fill=CHROME)
    for index, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        draw.ellipse([16 + index * 22, 10, 28 + index * 22, 22], fill=color)
    draw.text((92, 9), title, font=load_font(13), fill=MUTED)

    for row, line in enumerate(lines):
        color = FG
        stripped = line.strip()
        if line.startswith("$"):
            color = ACCENT
        elif stripped.startswith("share x="):
            color = "#1a7f37"
        elif stripped.startswith(("Subset", "Split", "=", "threshold", "subsets")):
            color = MUTED
        elif "total" in stripped:
            color = MUTED
        draw.text((pad, 50 + row * line_height), line, font=font, fill=color)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)


def render_subset_grid(rows: list[dict], out_path: Path) -> None:
    figure, axis = plt.subplots(figsize=(8.6, 3.4))
    figure.patch.set_facecolor("#ffffff")
    labels = [f"{row['threshold']} of {row['shares']}" for row in rows]
    success = [row["success"] * 100 for row in rows]
    bars = axis.bar(labels, success, color="#1a7f37", width=0.5)
    for bar, row in zip(bars, rows, strict=True):
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{row['subsets_ok']}/{row['subsets_tested']} subsets",
            ha="center",
            fontsize=8,
            color="#24292f",
        )
    axis.set_ylim(0, 118)
    axis.set_ylabel("% of k-subsets that reconstruct the secret")
    axis.set_title("Every k-subset works, and nothing below k does", fontsize=10, loc="left")
    axis.grid(axis="y", linestyle=":", alpha=0.45)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    figure.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(out_path, format="png", dpi=150)
    plt.close(figure)


def render_expansion(rows: list[dict], out_path: Path) -> None:
    figure, axis = plt.subplots(figsize=(8.6, 3.4))
    figure.patch.set_facecolor("#ffffff")
    for threshold in sorted({row["threshold"] for row in rows}):
        subset = [row for row in rows if row["threshold"] == threshold]
        axis.plot(
            [row["secret_bytes"] for row in subset],
            [row["expansion"] for row in subset],
            marker="o",
            label=f"{threshold} of {subset[0]['shares']}",
        )
    axis.set_xlabel("secret size in bytes")
    axis.set_ylabel("total share bytes / secret bytes")
    heading = "Expansion collapses with secret size: the x coordinate is a fixed tax"
    axis.set_title(heading, fontsize=10, loc="left")
    axis.grid(linestyle=":", alpha=0.45)
    axis.legend(fontsize=8, frameon=False, title="threshold", title_fontsize=8)
    for spine in ("top", "right"):
        axis.spines[spine].set_visible(False)
    figure.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(out_path, format=out_path.suffix.lstrip("."))
    plt.close(figure)


def main() -> int:
    images = ROOT / "docs" / "images"
    images.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)

    subset_rows = []
    for threshold, shares in CONFIGS:
        report = verify_all_subsets(SECRET, threshold=threshold, shares=shares,
                                    rng=secrets.SystemRandom(7))
        subset_rows.append(report.as_dict())

    spread_rows = []
    for threshold, shares in CONFIGS:
        trials = 96
        distinct = below_threshold_spread(SECRET, threshold=threshold, shares=shares,
                                           trials=trials, rng=secrets.SystemRandom(11))
        spread_rows.append((threshold - 1, trials, distinct))

    rows = size_table()
    sample_shares = split(SECRET, threshold=3, shares=5, rng=secrets.SystemRandom(3))

    payload = {
        "secret_bytes": len(SECRET),
        "subsets": subset_rows,
        "below_threshold": [
            {"holding": holding, "trials": trials, "distinct": distinct}
            for holding, trials, distinct in spread_rows
        ],
        "sizes": rows,
        "sample_share": sample_shares[0].as_dict(),
    }
    (ROOT / "docs" / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    terminal = (
        "$ share-lab split --secret \"vault-unseal-token\" -k 3 -n 5\n\n"
        + render_summary(SECRET, 3, 5)
        + "\n\n"
        + render_shares(sample_shares)
        + "\n\n$ share-lab verify --secret \"vault-unseal-token\" -k 3 -n 5\n\n"
        + render_subset_report(verify_all_subsets(SECRET, threshold=3, shares=5))
        + "\n$ share-lab below-threshold -k 3 -n 5 --trials 96\n\n"
        + render_below_threshold(spread_rows)
        + "\n$ share-lab sizes\n\n"
        + render_size_table(rows[:6])
    )
    title = "share-lab  -  Shamir over GF(256), measured"
    render_terminal(terminal, images / "lab.png", title)
    render_subset_grid(subset_rows, images / "subsets.png")
    render_expansion(rows, images / "expansion.svg")

    print(
        " | ".join(
            f"{row['threshold']}of{row['shares']}={row['subsets_ok']}/{row['subsets_tested']}"
            for row in subset_rows
        )
        + f" | below-k distinct {[distinct for _h, _t, distinct in spread_rows]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
