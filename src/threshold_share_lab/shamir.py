"""Shamir secret sharing over GF(2^8).

A secret is split into *n* shares such that any *k* of them reconstruct it and any *k-1* reveal
nothing. The maths is a polynomial of degree ``k-1`` with the secret as its constant term,
evaluated at *n* distinct non-zero points; reconstruction is Lagrange interpolation at zero.

GF(2^8) means one byte per coefficient, so every operation is a table lookup - no big integers,
no floating point, and no library.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

POLYNOMIAL = 0x11B  # x^8 + x^4 + x^3 + x + 1, the AES field


class ShareError(ValueError):
    """Raised for invalid share parameters or share sets."""


def _build_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Log/antilog tables built from the generator 3.

    Note that 2 is *not* a generator for the AES polynomial 0x11B - its multiplicative order is
    only 51, so a table built by repeated doubling has 51 distinct entries and silently breaks
    multiplication. 3 has full order 255.
    """
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for index in range(255):
        exp[index] = value
        log[value] = index
        doubled = value << 1
        if doubled & 0x100:
            doubled ^= POLYNOMIAL
        value ^= doubled  # multiply by 3: x*3 == x*2 ^ x
    for index in range(255, 512):
        exp[index] = exp[index - 255]
    return tuple(exp), tuple(log)


EXP, LOG = _build_tables()


def mul(left: int, right: int) -> int:
    if left == 0 or right == 0:
        return 0
    return EXP[LOG[left] + LOG[right]]


def div(left: int, right: int) -> int:
    if right == 0:
        raise ShareError("division by zero in GF(256)")
    if left == 0:
        return 0
    return EXP[(LOG[left] - LOG[right]) % 255]


def inverse(value: int) -> int:
    if value == 0:
        raise ShareError("zero has no multiplicative inverse")
    return EXP[255 - LOG[value]]


@dataclass(frozen=True)
class Share:
    x: int
    payload: bytes

    def as_dict(self) -> dict:
        return {"x": self.x, "payload": self.payload.hex()}


def split(
    secret: bytes,
    *,
    threshold: int,
    shares: int,
    rng: secrets.SystemRandom | None = None,
) -> list[Share]:
    """Split ``secret`` into ``shares`` shares, any ``threshold`` of which reconstruct it."""
    if not secret:
        raise ShareError("secret is empty")
    if threshold < 2:
        raise ShareError("threshold must be at least 2")
    if shares < threshold:
        raise ShareError("shares must be at least the threshold")
    if shares > 255:
        raise ShareError("a non-zero GF(256) coordinate limits shares to 255")
    random = rng or secrets.SystemRandom()

    coefficients: list[list[int]] = []
    for byte in secret:
        row = [byte] + [random.randrange(1, 256) for _ in range(threshold - 1)]
        coefficients.append(row)

    result: list[Share] = []
    for x in range(1, shares + 1):
        payload = bytearray()
        for row in coefficients:
            value = 0
            for power, coefficient in enumerate(row):
                value ^= mul(coefficient, _pow(x, power))
            payload.append(value)
        result.append(Share(x=x, payload=bytes(payload)))
    return result


def _pow(base: int, exponent: int) -> int:
    if exponent == 0:
        return 1
    if base == 0:
        return 0
    return EXP[(LOG[base] * exponent) % 255]


def combine(shares: list[Share]) -> bytes:
    """Reconstruct the secret from a set of shares via Lagrange interpolation at x = 0."""
    if not shares:
        raise ShareError("no shares given")
    coordinates = {share.x for share in shares}
    if len(coordinates) != len(shares):
        raise ShareError("duplicate share coordinates")
    if len({len(share.payload) for share in shares}) != 1:
        raise ShareError("shares have different lengths")
    if any(share.x == 0 for share in shares):
        raise ShareError("share coordinate must be non-zero")

    length = len(shares[0].payload)
    secret = bytearray()
    for index in range(length):
        total = 0
        for share in shares:
            numerator = 1
            denominator = 1
            for other in shares:
                if other.x == share.x:
                    continue
                numerator = mul(numerator, other.x)
                denominator = mul(denominator, share.x ^ other.x)
            total ^= mul(share.payload[index], div(numerator, denominator))
        secret.append(total)
    return bytes(secret)


def describe(secret: bytes, threshold: int, shares: int) -> dict:
    return {
        "secret_bytes": len(secret),
        "threshold": threshold,
        "shares": shares,
        "share_bytes": len(secret) + 1,
        "total_share_bytes": shares * (len(secret) + 1),
        "expansion": (shares * (len(secret) + 1)) / len(secret) if secret else 0.0,
        "combinations": _combinations(shares, threshold),
    }


def _combinations(n: int, k: int) -> int:
    if k < 0 or k > n:
        return 0
    result = 1
    for index in range(k):
        result = result * (n - index) // (index + 1)
    return result


def choose_subsets(
    shares: list[Share], threshold: int, limit: int | None = None
) -> list[list[Share]]:
    """Every k-subset of the shares, or at most ``limit`` of them (deterministically)."""
    from itertools import combinations

    subsets = [list(combo) for combo in combinations(shares, threshold)]
    return subsets[:limit] if limit is not None else subsets


def brute_force_space(threshold: int) -> int:
    """How many candidate secrets a k-1 share attack still has to search."""
    return 256**threshold
