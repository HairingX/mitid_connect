"""Ready-made steps of a NemLog-in login flow around the MitID browser client."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
from collections.abc import Mapping
from typing import Any

import aiohttp
from bs4 import BeautifulSoup, Tag
from Cryptodome import Random

from .browser_client import MITID_URL, BrowserClient, MitIDError

_LOGGER = logging.getLogger(__name__)


async def get_authentication_code(
    session: aiohttp.ClientSession,
    aux: Mapping[str, Any],
    method: str,
    user_id: str,
    headers: Mapping[str, str] | None = None,
    base_url: str = MITID_URL,
) -> str:
    """Log `user_id` in with the MitID app, from NemLog-in's parameters `aux`, and give the code.

    Raises:
        NotImplementedError: `method` is "TOKEN", which needs the token's digits and the password.
        MitIDError: the method is unknown, or not one the user has.
    """
    client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode("ascii")
    client = BrowserClient(
        session, client_hash, str(aux["parameters"]["authenticationSessionId"]), headers, base_url=base_url
    )
    await client.start()
    available = await client.identify_as_user_and_get_available_authenticators(user_id)
    if method not in ("APP", "TOKEN"):
        raise MitIDError(f"Unknown authenticator method: {method}")
    if method not in available:
        raise MitIDError(f"The {method} authenticator is not one the MitID user has")
    if method == "TOKEN":
        raise NotImplementedError("Log in with a code token through BrowserClient, with its digits and the password")
    await client.authenticate_with_app()
    return await client.finalize_authentication_and_get_authorization_code()


async def choose_between_multiple_identitites(
    session: aiohttp.ClientSession, url: str, soup: BeautifulSoup, identity_index: int = 0
) -> tuple[str, BeautifulSoup]:
    """Choose one of several identities on NemLog-in's page at `url`, and give the next page.

    Raises:
        ValueError: `identity_index` is not one of the identities offered.
    """
    form = soup.form
    if form is None:
        raise ValueError("The page offers no identities to choose between")
    data: dict[str, str] = {}
    for field in form.select("input"):
        name = field.get("name")
        if isinstance(name, str):
            value = field.get("value")
            data[name] = value if isinstance(value, str) else ""
    options = soup.select("div.list-link-box")
    if identity_index < 0 or identity_index >= len(options):
        raise ValueError(f"Identity index {identity_index} out of range (0-{len(options) - 1})")
    link = options[identity_index].a
    if not isinstance(link, Tag):
        raise ValueError("The identity offered has no link to choose it by")
    data["ChosenOptionJson"] = str(link["data-loginoptions"])
    _LOGGER.debug("Choosing identity %s of %s", identity_index + 1, len(options))
    async with session.post(url, data=data) as response:
        text = await response.text()
        next_url = str(response.url)
    return next_url, BeautifulSoup(text, "xml")


def _random_string() -> str:
    return binascii.hexlify(Random.new().read(28)).decode("utf-8")


def _challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")


def generate_nem_login_parameters() -> tuple[str, str, str, str]:
    """A fresh state, nonce, PKCE code verifier and its S256 code challenge for NemLog-in."""
    verifier = _random_string()
    return _random_string(), _random_string(), verifier, _challenge(verifier)
