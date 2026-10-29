"""Tests of a MitID app login against the simulated MitID."""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
from typing import Any

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from bs4 import BeautifulSoup

from mitid_connect import (
    BrowserClient,
    MitIDError,
    choose_between_multiple_identitites,
    get_authentication_code,
)
from mitid_connect.testing import SimulatedMitID


async def _client(mitid: SimulatedMitID, session: aiohttp.ClientSession) -> BrowserClient:
    aux = mitid.new_login()
    client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode("ascii")
    client = BrowserClient(
        session, client_hash, aux["parameters"]["authenticationSessionId"], base_url=mitid.url
    )
    await client.start()
    return client


def test_an_app_login_gives_the_authorization_code() -> None:
    async def login() -> str:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            return await get_authentication_code(session, mitid.new_login(), "APP", "parent", base_url=mitid.url)

    assert asyncio.run(login()) == "simulated-authorization-code"


def test_the_login_shows_the_qr_codes_until_they_are_scanned() -> None:
    async def login() -> list[tuple[str, bool]]:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            client = await _client(mitid, session)
            assert await client.identify_as_user_and_get_available_authenticators("parent") == {"APP": "MitID app"}
            await client.start_app_authentication()
            steps: list[tuple[str, bool]] = []
            while True:
                result = await client.poll_app_authentication_status()
                steps.append((str(result["status"]), client.get_current_qr_codes() is not None))
                if result["status"] == "completed":
                    break
            await client.complete_app_authentication()
            assert await client.finalize_authentication_and_get_authorization_code() == mitid.authorization_code
            return steps

    assert asyncio.run(login()) == [("waiting", False), ("qr_ready", True), ("verified", False), ("completed", False)]


def test_the_app_can_be_asked_to_show_a_code_instead() -> None:
    async def login() -> dict[str, Any]:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            mitid.app_answers = ["channel_validation_otp"]
            client = await _client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            await client.start_app_authentication()
            return await client.poll_app_authentication_status()

    result = asyncio.run(login())
    assert result["status"] == "otp_ready"
    assert result["otp_code"] == "a1b2c3d4"


def test_a_login_the_app_refuses_fails(caplog: pytest.LogCaptureFixture) -> None:
    async def login() -> None:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            mitid.app_answers = ["timeout", "REJECTED"]
            await get_authentication_code(session, mitid.new_login(), "APP", "parent", base_url=mitid.url)

    with pytest.raises(MitIDError, match="not accepted"):
        asyncio.run(login())


def test_an_unknown_user_fails_without_the_user_id_in_the_error_or_the_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    async def login() -> None:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            await get_authentication_code(session, mitid.new_login(), "APP", "secret-user", base_url=mitid.url)

    with pytest.raises(MitIDError) as raised:
        asyncio.run(login())
    assert "secret-user" not in str(raised.value)
    assert "secret-user" not in caplog.text


@pytest.mark.parametrize(("method", "error"), [("TOKEN", MitIDError), ("SMS", MitIDError)])
def test_a_method_the_user_does_not_have_fails(method: str, error: type[Exception]) -> None:
    async def login() -> None:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            await get_authentication_code(session, mitid.new_login(), method, "parent", base_url=mitid.url)

    with pytest.raises(error):
        asyncio.run(login())


def test_a_wrong_proof_is_refused() -> None:
    async def login() -> None:
        async with SimulatedMitID() as mitid, aiohttp.ClientSession() as session:
            client = await _client(mitid, session)
            await client.identify_as_user_and_get_available_authenticators("parent")
            client.client_hash = "00" * 32
            await client.authenticate_with_app()

    with pytest.raises(MitIDError, match="HTTP 400"):
        asyncio.run(login())


def test_an_identity_is_chosen_on_nemlog_ins_page() -> None:
    page = """<html><form><input name="__RequestVerificationToken" value="t"/><input name="Empty"/></form>
    <div class="list-link-box"><a data-loginoptions='{"id":1}'><div class="list-link-text">Parent</div></a></div>
    <div class="list-link-box"><a data-loginoptions='{"id":2}'><div class="list-link-text">Teacher</div></a></div>
    </html>"""
    posted: dict[str, str] = {}

    async def choose(request: web.Request) -> web.Response:
        posted.update({key: str(value) for key, value in (await request.post()).items()})
        return web.Response(text="<SAMLResponse>done</SAMLResponse>")

    async def run() -> tuple[str, BeautifulSoup]:
        app = web.Application()
        app.router.add_post("/loginoption", choose)
        async with TestServer(app) as server, aiohttp.ClientSession() as session:
            return await choose_between_multiple_identitites(
                session, str(server.make_url("/loginoption")), BeautifulSoup(page, "html.parser"), 1
            )

    url, soup = asyncio.run(run())
    assert url.endswith("/loginoption")
    assert posted == {"__RequestVerificationToken": "t", "Empty": "", "ChosenOptionJson": '{"id":2}'}
    assert soup.find("SAMLResponse") is not None


def test_an_identity_that_is_not_offered_cannot_be_chosen() -> None:
    page = '<form></form><div class="list-link-box"><a data-loginoptions="1"></a></div>'

    async def run() -> None:
        async with aiohttp.ClientSession() as session:
            await choose_between_multiple_identitites(session, "http://192.0.2.1/", BeautifulSoup(page, "html.parser"), 3)

    with pytest.raises(ValueError):
        asyncio.run(run())
