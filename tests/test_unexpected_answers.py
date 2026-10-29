"""Tests of how the browser client takes answers MitID gives only when something goes wrong."""

from __future__ import annotations

import asyncio

import aiohttp
import pytest

from mitid_connect import MitIDError
from mitid_connect.testing import SimulatedMitID, User
from simulation import answer_instead, started_client

APP_AND_TOKEN = {"parent": User(app=True, code_token=True)}
TOKEN_ONLY = {"parent": User(app=False, code_token=True)}
NEXT = "/next"
AUTHENTICATOR = {
    "authenticatorType": "APP",
    "authenticatorSessionFlowKey": "flow-key",
    "eafeHash": "eafe",
    "authenticatorSessionId": "authenticator-session",
}


def _fails(mitid: SimulatedMitID, steps: str, match: str) -> None:
    """Log in to `mitid` with the authenticator `steps` names, if any, and check it fails with `match`."""

    async def run() -> None:
        async with mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            if steps == "app":
                await client.authenticate_with_app()
            elif steps == "token":
                await client.authenticate_with_token(TOKEN_ONLY["parent"].token_digits)
                await client.authenticate_with_password(TOKEN_ONLY["parent"].password)

    with pytest.raises(MitIDError, match=match):
        asyncio.run(run())


def test_an_answer_that_is_not_json_is_a_failure_with_its_status() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "GET", "", 502, "<html>Bad gateway</html>")

    async def run() -> None:
        async with mitid, aiohttp.ClientSession() as session:
            await started_client(mitid, session)

    with pytest.raises(MitIDError, match=r"^Reading the authentication session failed: HTTP 502$"):
        asyncio.run(run())


def test_the_users_authenticators_that_cannot_be_read_fail_with_mitids_error_code() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "POST", NEXT, 503, {"errorCode": "core.unavailable"})
    _fails(mitid, "", r"Reading the user's authenticators failed: HTTP 503 \(core.unavailable\)")


def test_an_authenticator_the_client_cannot_use_is_left_out() -> None:
    mitid = SimulatedMitID()
    combinations = [
        {"id": "X9", "combinationItems": [{"name": "Chip"}]},
        {"id": "S3", "combinationItems": [{"name": "MitID app"}]},
    ]
    answer_instead(
        mitid, "POST", NEXT, 200, {"errors": [], "nextAuthenticator": AUTHENTICATOR, "combinations": combinations}
    )

    async def run() -> dict[str, str]:
        async with mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            return await client.identify_as_user_and_get_available_authenticators("parent")

    assert asyncio.run(run()) == {"APP": "MitID app"}


def test_a_user_with_only_authenticators_the_client_cannot_use_fails() -> None:
    mitid = SimulatedMitID()
    combinations = [{"id": "X9", "combinationItems": [{"name": "Chip"}]}]
    answer_instead(
        mitid, "POST", NEXT, 200, {"errors": [], "nextAuthenticator": AUTHENTICATOR, "combinations": combinations}
    )
    _fails(mitid, "", "no authenticator this client can use")


def test_an_authenticator_that_cannot_be_chosen_fails() -> None:
    mitid = SimulatedMitID(APP_AND_TOKEN)
    answer_instead(mitid, "POST", NEXT, 503, {}, skip=1)
    _fails(mitid, "token", "Choosing the authenticator failed: HTTP 503")


def test_another_authenticator_than_the_one_chosen_fails() -> None:
    mitid = SimulatedMitID(APP_AND_TOKEN)
    answer_instead(mitid, "POST", NEXT, 200, {"errors": [], "nextAuthenticator": AUTHENTICATOR}, skip=1)
    _fails(mitid, "token", r"desired authenticator \(TOKEN\), instead we received \(APP\)")


def test_a_code_token_that_cannot_be_started_fails() -> None:
    mitid = SimulatedMitID(TOKEN_ONLY)
    answer_instead(mitid, "POST", "/codetoken-init", 500)
    _fails(mitid, "token", "Starting the code token failed: HTTP 500")


def test_a_code_token_that_is_not_accepted_fails() -> None:
    mitid = SimulatedMitID(TOKEN_ONLY)
    answer_instead(mitid, "POST", NEXT, 503, skip=1)
    _fails(mitid, "token", "Accepting the code token failed: HTTP 503")


def test_a_code_token_followed_by_anything_but_the_password_fails() -> None:
    mitid = SimulatedMitID(TOKEN_ONLY)
    answer_instead(mitid, "POST", NEXT, 200, {"errors": [], "nextAuthenticator": AUTHENTICATOR}, skip=1)
    _fails(mitid, "token", "something else than the password")


def test_a_password_that_cannot_be_started_fails() -> None:
    mitid = SimulatedMitID(TOKEN_ONLY)
    answer_instead(mitid, "POST", "/init", 500)
    _fails(mitid, "token", "Starting the password failed: HTTP 500")


def test_parallel_app_logins_fail() -> None:
    mitid = SimulatedMitID()
    answer_instead(
        mitid, "POST", "/init-auth", 200, {"errorCode": "auth.codeapp.authentication.parallel_sessions_detected"}
    )
    _fails(mitid, "app", "Parallel app sessions detected")


def test_an_app_proof_that_cannot_be_started_fails() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "POST", "/init", 500)
    _fails(mitid, "app", "Starting the app's proof failed: HTTP 500")


def test_a_server_proof_that_does_not_match_the_session_key_fails() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "POST", "/prove", 200, {"m2": {"value": "00"}})
    _fails(mitid, "app", "m2 could not be validated")


def test_an_app_login_mitid_does_not_accept_in_the_end_fails() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "POST", NEXT, 200, {"errors": [{"errorCode": "core.refused"}]}, skip=1)
    _fails(mitid, "app", "Could not prove the app login")


def test_a_server_value_that_fails_srps_safety_check_is_refused() -> None:
    mitid = SimulatedMitID()
    answer_instead(mitid, "POST", "/init", 200, {"srpSalt": {"value": "00"}, "randomB": {"value": "0"}})

    async def run() -> None:
        async with mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            await client.authenticate_with_app()

    with pytest.raises(MitIDError, match="invalid SRP value"):
        asyncio.run(run())
