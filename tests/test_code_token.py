"""Tests of a MitID code token login, with its password, against the simulated MitID."""

from __future__ import annotations

import asyncio
import logging

import aiohttp
import pytest

from mitid_connect import MitIDError, get_authentication_code
from mitid_connect.testing import SimulatedMitID, User
from simulation import started_client

TOKEN_USER = User(app=False, code_token=True, token_digits="654321", password="secret-password")


async def _log_in(mitid: SimulatedMitID, user_id: str, digits: str, password: str) -> str:
    async with aiohttp.ClientSession() as session:
        client = await started_client(mitid, session)
        await client.identify_as_user_and_get_available_authenticators(user_id)
        await client.authenticate_with_token(digits)
        await client.authenticate_with_password(password)
        return await client.finalize_authentication_and_get_authorization_code()


def test_a_code_token_login_gives_the_authorization_code() -> None:
    async def run() -> str:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid:
            return await _log_in(mitid, "parent", "654321", "secret-password")

    assert asyncio.run(run()) == "simulated-authorization-code"


def test_a_user_with_the_app_and_a_code_token_can_choose_the_code_token() -> None:
    user = User(app=True, code_token=True, token_digits="111111", password="pw")

    async def run() -> tuple[dict[str, str], str]:
        async with SimulatedMitID({"parent": user}) as mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            available = await client.identify_as_user_and_get_available_authenticators("parent")
            await client.authenticate_with_token("111111")
            await client.authenticate_with_password("pw")
            return available, await client.finalize_authentication_and_get_authorization_code()

    assert asyncio.run(run()) == ({"APP": "MitID app", "TOKEN": "Code token"}, "simulated-authorization-code")


def test_wrong_digits_fail_without_the_digits_in_the_error_or_the_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid:
            await _log_in(mitid, "parent", "999999", "secret-password")

    with pytest.raises(MitIDError, match="did not accept the code token's digits") as raised:
        asyncio.run(run())
    assert "999999" not in str(raised.value)
    assert "999999" not in caplog.text


def test_the_digits_can_be_given_again_after_wrong_ones() -> None:
    async def run() -> str:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            with pytest.raises(MitIDError):
                await client.authenticate_with_token("999999")
            await client.authenticate_with_token("654321")
            await client.authenticate_with_password("secret-password")
            return await client.finalize_authentication_and_get_authorization_code()

    assert asyncio.run(run()) == "simulated-authorization-code"


def test_a_wrong_password_fails_without_the_password_in_the_error_or_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid:
            await _log_in(mitid, "parent", "654321", "wrong-password")

    with pytest.raises(MitIDError, match=r"did not accept the password \(PASSWORD_INVALID\)") as raised:
        asyncio.run(run())
    assert "wrong-password" not in str(raised.value)
    assert "wrong-password" not in caplog.text


def test_the_password_cannot_be_given_before_the_code_token() -> None:
    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            await client.authenticate_with_password("secret-password")

    with pytest.raises(MitIDError, match="before completing authentication with token"):
        asyncio.run(run())


def test_a_code_token_proof_for_another_flow_key_is_refused() -> None:
    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            client.current_authenticator_session_flow_key = "another-flow-key"
            await client.authenticate_with_token("654321")

    with pytest.raises(MitIDError, match=r"Proving the code token failed: HTTP 400 \(auth.codetoken.proof_invalid\)"):
        asyncio.run(run())


def test_a_password_flow_value_proof_for_another_client_is_refused() -> None:
    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid, aiohttp.ClientSession() as session:
            client = await started_client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            await client.authenticate_with_token("654321")
            client.client_hash = "00" * 32
            await client.authenticate_with_password("secret-password")

    with pytest.raises(MitIDError, match=r"Proving the password failed: HTTP 400 \(auth.password.proof_invalid\)"):
        asyncio.run(run())


def test_the_ready_made_login_leaves_the_code_token_to_the_browser_client() -> None:
    async def run() -> None:
        async with SimulatedMitID({"parent": TOKEN_USER}) as mitid, aiohttp.ClientSession() as session:
            await get_authentication_code(session, mitid.new_login(), "TOKEN", "parent", base_url=mitid.url)

    with pytest.raises(NotImplementedError):
        asyncio.run(run())
