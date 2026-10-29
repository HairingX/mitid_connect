"""Stress tests of the MitID login against a simulated MitID with a slow and failing network."""

from __future__ import annotations

import asyncio
import time

import aiohttp
import pytest

from mitid_connect import MitIDError, get_authentication_code
from mitid_connect.testing import Network, SimulatedMitID

LOGINS = 25


def test_many_logins_at_once_each_finish_while_the_others_wait_on_the_network() -> None:
    """Twenty-five logins of about twelve requests each, 20-60 ms apiece: run one after the
    other they would take over ten seconds."""

    async def run() -> tuple[list[str], float, Network]:
        network = Network(latency=(0.02, 0.06), seed=1)
        async with SimulatedMitID(users={f"user{index}" for index in range(LOGINS)}, network=network) as mitid:
            async with aiohttp.ClientSession() as session:
                started = time.monotonic()
                codes = await asyncio.gather(
                    *(
                        get_authentication_code(session, mitid.new_login(), "APP", f"user{index}", base_url=mitid.url)
                        for index in range(LOGINS)
                    )
                )
                return codes, time.monotonic() - started, network

    codes, elapsed, network = asyncio.run(run())
    assert codes == [SimulatedMitID().authorization_code] * LOGINS
    assert network.requests >= LOGINS * 10
    assert network.most_concurrent >= LOGINS
    assert elapsed < 5


def test_a_mitid_that_fails_ends_the_login_with_an_error_not_a_hang() -> None:
    async def run() -> None:
        async with SimulatedMitID(network=Network(latency=0.01, failure_rate=1.0)) as mitid:
            async with aiohttp.ClientSession() as session:
                async with asyncio.timeout(5):
                    await get_authentication_code(session, mitid.new_login(), "APP", "parent", base_url=mitid.url)

    with pytest.raises(MitIDError, match="HTTP 503"):
        asyncio.run(run())


def test_a_login_slower_than_its_timeout_fails_with_a_timeout() -> None:
    async def run() -> None:
        async with SimulatedMitID(network=Network(latency=0.5)) as mitid:
            async with aiohttp.ClientSession() as session:
                from mitid_connect import BrowserClient

                aux = mitid.new_login()
                client = BrowserClient(
                    session, "00", aux["parameters"]["authenticationSessionId"], timeout=0.1, base_url=mitid.url
                )
                await client.start()

    with pytest.raises(TimeoutError):
        asyncio.run(run())
