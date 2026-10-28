"""Experiments: does reconstruction work for every subset, and what does losing shares cost?"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .shamir import Share, ShareError, choose_subsets, combine, describe, split


@dataclass(frozen=True)
class SubsetReport:
    threshold: int
    shares: int
    subsets_tested: int
    subsets_ok: int
    distinct_secrets_from_below_threshold: int

    @property
    def success(self) -> float:
        return self.subsets_ok / self.subsets_tested if self.subsets_tested else 0.0

    def as_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "shares": self.shares,
            "subsets_tested": self.subsets_tested,
            "subsets_ok": self.subsets_ok,
            "success": round(self.success, 4),
            "distinct_secrets_from_below_threshold": self.distinct_secrets_from_below_threshold,
        }


def verify_all_subsets(
    secret: bytes, *, threshold: int, shares: int, limit: int | None = None,
    rng: secrets.SystemRandom | None = None,
) -> SubsetReport:
    """Reconstruct from every k-subset and count the successes."""
    split_shares = split(secret, threshold=threshold, shares=shares, rng=rng)
    subsets = choose_subsets(split_shares, threshold, limit)
    ok = 0
    for subset in subsets:
        try:
            if combine(subset) == secret:
                ok += 1
        except ShareError:
            pass
    return SubsetReport(
        threshold=threshold,
        shares=shares,
        subsets_tested=len(subsets),
        subsets_ok=ok,
        distinct_secrets_from_below_threshold=0,
    )


def below_threshold_spread(
    secret: bytes, *, threshold: int, shares: int, trials: int = 32,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """How many *different* candidate secrets k-1 shares produce when combined anyway.

    Combining k-1 shares is not "almost right": it yields a value that is unrelated to the real
    secret, and each different set of k-1 shares yields a different value. That is the point of
    the scheme, and it is measurable.
    """
    candidates: set[bytes] = set()
    for _ in range(trials):
        split_shares = split(secret, threshold=threshold, shares=shares, rng=rng)
        subset = split_shares[: threshold - 1]
        if not subset:
            continue
        candidates.add(combine(subset))
    candidates.discard(secret)
    return len(candidates)


def size_table(
    secret_sizes: tuple[int, ...] = (16, 32, 64), thresholds: tuple[int, ...] = (2, 3, 5)
) -> list[dict]:
    rows = []
    for size in secret_sizes:
        for threshold in thresholds:
            info = describe(bytes(size), threshold, threshold + 2)
            info["secret_bytes"] = size
            rows.append(info)
    return rows


def subset_count_table(shares: int, threshold: int) -> int:
    return len(choose_subsets([Share(x=index, payload=b"\x00") for index in range(1, shares + 1)],
                              threshold))
