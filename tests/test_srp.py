"""Tests of the SRP arithmetic and encodings the MitID client speaks."""

import base64
import binascii
import hashlib

import pytest

from mitid_connect.srp import (
    AesDecryptWithKey,
    CustomSRP,
    bytes_to_hex,
    bytes_to_int,
    hex_to_bytes,
    hex_to_int,
    int_to_bytes,
    int_to_hex,
    pad,
    unpad,
)


def test_numbers_round_trip_through_hex_and_bytes() -> None:
    assert int_to_hex(255) == "ff"
    assert hex_to_int("ff") == 255
    assert int_to_bytes(258) == b"\x01\x02"
    assert bytes_to_int(b"\x01\x02") == 258
    assert bytes_to_hex(b"\x01\xab") == "01ab"
    assert hex_to_bytes("01ab") == b"\x01\xab"


def test_padding_fills_a_block_and_comes_off_again() -> None:
    padded = pad("abc")
    assert len(padded) % 16 == 0
    assert unpad(padded) == "abc"


def test_a_message_encrypted_with_the_session_key_decrypts_with_it() -> None:
    srp = CustomSRP()
    srp.K_bits = hashlib.sha256(b"key").digest()
    message = base64.b64encode(srp.AuthEnc(b"secret"))
    assert srp.AuthDec(message) == b"secret"
    assert AesDecryptWithKey(message, srp.K_bits) == b"secret"


def test_stage_one_gives_the_public_value_of_a_fresh_secret() -> None:
    srp = CustomSRP()
    public = srp.SRPStage1()
    assert hex_to_int(public) == pow(srp.g, srp.a, srp.n)
    assert 0 < srp.a < 2**256


@pytest.mark.parametrize("random_b", ["0", "n"])
def test_a_server_value_that_is_a_multiple_of_the_modulus_is_refused(random_b: str) -> None:
    srp = CustomSRP()
    srp.SRPStage1()
    with pytest.raises(ValueError, match="safety check"):
        srp.SRPStage3("00", int_to_hex(srp.n) if random_b == "n" else random_b, "password", "session")


def test_a_message_encrypted_with_the_pin_key_decrypts_with_it() -> None:
    srp = CustomSRP()
    srp.K_bits = hashlib.sha256(b"key").digest()
    pin_key = hashlib.sha256(binascii.hexlify(srp.K_bits) + b"PIN").digest()
    other = CustomSRP()
    other.K_bits = pin_key
    assert srp.AuthDecPin(base64.b64encode(other.AuthEnc(b"pin"))) == b"pin"
