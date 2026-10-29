"""Steps shared by the tests that log in to the simulated MitID."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp
from aiohttp import web

from mitid_connect import BrowserClient
from mitid_connect.testing import SimulatedMitID


async def started_client(mitid: SimulatedMitID, session: aiohttp.ClientSession) -> BrowserClient:
    """A browser client for a new login to `mitid`, which has read its authentication session."""
    aux = mitid.new_login()
    client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode("ascii")
    client = BrowserClient(session, client_hash, aux["parameters"]["authenticationSessionId"], base_url=mitid.url)
    await client.start()
    return client


def answer_instead(
    mitid: SimulatedMitID, method: str, path_end: str, status: int, body: Any = None, *, skip: int = 0
) -> None:
    """Have `mitid` answer the requests to a path ending in `path_end` itself, after the first `skip`.

    `body` is sent as JSON, or as it is when it is text. Call it before the server starts.
    """
    seen = 0

    @web.middleware
    async def instead(
        request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
    ) -> web.StreamResponse:
        nonlocal seen
        if request.method == method and request.path.endswith(path_end):
            seen += 1
            if seen > skip:
                if isinstance(body, str):
                    return web.Response(status=status, text=body)
                return web.json_response(body, status=status)
        return await handler(request)

    mitid.app.middlewares.append(instead)
