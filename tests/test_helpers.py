"""Tests of the NemLog-in parameters a login flow starts with."""

import base64
import hashlib

from mitid_connect import generate_nem_login_parameters


def test_the_code_challenge_is_the_verifiers_s256_hash() -> None:
    state, nonce, verifier, challenge = generate_nem_login_parameters()
    assert len({state, nonce, verifier}) == 3
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert challenge.rstrip("=") == expected
