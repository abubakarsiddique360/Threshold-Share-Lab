import pytest

from threshold_share_lab.shamir import (
    EXP,
    LOG,
    Share,
    ShareError,
    brute_force_space,
    choose_subsets,
    combine,
    describe,
    div,
    inverse,
    mul,
    split,
)

SECRET = b"vault-unseal-token"


def test_generator_has_full_order():
    # regression: generator 2 has order 51 for the AES polynomial, which breaks multiplication
    assert len(set(EXP[:255])) == 255
    assert LOG[3] == 1


def test_multiplication_known_values():
    assert mul(3, 3) == 5
    assert mul(5, 3) == 15
    assert mul(0, 7) == 0
    assert mul(1, 200) == 200


def test_inverse_round_trip_for_every_element():
    for value in range(1, 256):
        assert mul(value, inverse(value)) == 1


def test_division_inverts_multiplication():
    assert div(mul(9, 11), 11) == 9


def test_division_by_zero_rejected():
    with pytest.raises(ShareError, match="division by zero"):
        div(1, 0)


def test_inverse_of_zero_rejected():
    with pytest.raises(ShareError, match="no multiplicative inverse"):
        inverse(0)


def test_split_produces_requested_shares():
    shares = split(SECRET, threshold=3, shares=5)
    assert len(shares) == 5
    assert [share.x for share in shares] == [1, 2, 3, 4, 5]
    assert all(len(share.payload) == len(SECRET) for share in shares)


def test_shares_differ_from_each_other():
    shares = split(SECRET, threshold=3, shares=5)
    assert len({share.payload for share in shares}) == 5


def test_every_threshold_subset_reconstructs():
    shares = split(SECRET, threshold=3, shares=5)
    for subset in choose_subsets(shares, 3):
        assert combine(subset) == SECRET


def test_any_order_of_shares_works():
    shares = split(SECRET, threshold=2, shares=3)
    assert combine([shares[2], shares[0]]) == SECRET


def test_fewer_than_threshold_gives_a_wrong_secret():
    shares = split(SECRET, threshold=3, shares=5)
    recovered = combine(shares[:2])
    assert recovered != SECRET
    assert len(recovered) == len(SECRET)


def test_secret_of_one_byte():
    shares = split(b"\x00", threshold=2, shares=2)
    assert combine(shares) == b"\x00"


def test_two_of_two():
    shares = split(b"AB", threshold=2, shares=2)
    assert combine(shares) == b"AB"


def test_rejects_empty_secret():
    with pytest.raises(ShareError, match="secret is empty"):
        split(b"", threshold=2, shares=3)


def test_rejects_threshold_below_two():
    with pytest.raises(ShareError, match="at least 2"):
        split(SECRET, threshold=1, shares=3)


def test_rejects_too_few_shares():
    with pytest.raises(ShareError, match="at least the threshold"):
        split(SECRET, threshold=4, shares=3)


def test_rejects_more_than_255_shares():
    with pytest.raises(ShareError, match="255"):
        split(SECRET, threshold=2, shares=256)


def test_combine_rejects_no_shares():
    with pytest.raises(ShareError, match="no shares"):
        combine([])


def test_combine_rejects_duplicate_coordinates():
    share = Share(x=1, payload=b"\x01")
    with pytest.raises(ShareError, match="duplicate share"):
        combine([share, share])


def test_combine_rejects_mismatched_lengths():
    with pytest.raises(ShareError, match="different lengths"):
        combine([Share(x=1, payload=b"\x01"), Share(x=2, payload=b"\x01\x02")])


def test_combine_rejects_zero_coordinate():
    with pytest.raises(ShareError, match="non-zero"):
        combine([Share(x=0, payload=b"\x01")])


def test_describe_numbers():
    info = describe(b"x" * 16, 3, 5)
    assert info["share_bytes"] == 17
    assert info["total_share_bytes"] == 85
    assert info["combinations"] == 10
    assert info["expansion"] == pytest.approx(85 / 16)


def test_choose_subsets_count_matches_binomial():
    shares = split(SECRET, threshold=3, shares=6)
    assert len(choose_subsets(shares, 3)) == 20
    assert len(choose_subsets(shares, 3, limit=4)) == 4


def test_brute_force_space():
    assert brute_force_space(3) == 256**3


def test_share_serialises():
    assert Share(x=7, payload=b"\x01\x02").as_dict() == {"x": 7, "payload": "0102"}
