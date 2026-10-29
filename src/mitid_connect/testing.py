"""A simulated MitID, for tests: it answers the browser client's logins as MitID does.

It checks what a real MitID checks of the client - the SRP proof, the flow value proof, and for
the app its signature, encrypted with the agreed key - so a test of a login exercises the
protocol, not only its requests. The MitID app and the code token, with its password, are
simulated.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import random
import secrets
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self, cast

from aiohttp import web
from aiohttp.test_utils import TestServer

from .srp import AesDecryptWithKey, CustomSRP, bytes_to_hex, hex_to_int, int_to_hex, pad


@dataclass
class Network:
    """How a simulated server's network behaves: how long each answer takes, and how often it fails.

    `latency` is seconds, or a (shortest, longest) range drawn from for each request. A failing
    request is answered 503 after its latency, as an overloaded server answers.
    """

    latency: float | tuple[float, float] = 0.0
    failure_rate: float = 0.0
    seed: int | None = None
    requests: int = 0
    """Requests answered so far."""
    failures: int = 0
    """Requests answered with a failure so far."""
    concurrent: int = 0
    most_concurrent: int = 0
    """The most requests that were waiting for an answer at the same time."""

    def __post_init__(self) -> None:
        self._random = random.Random(self.seed)

    def delay(self) -> float:
        """The latency of the next answer, in seconds."""
        if isinstance(self.latency, tuple):
            return self._random.uniform(*self.latency)
        return self.latency

    async def answer(
        self, request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
    ) -> web.StreamResponse:
        """Answer `request` after the network's latency, or with its failure."""
        self.requests += 1
        self.concurrent += 1
        self.most_concurrent = max(self.most_concurrent, self.concurrent)
        try:
            await asyncio.sleep(self.delay())
            if self._random.random() < self.failure_rate:
                self.failures += 1
                return web.json_response({"message": "Service unavailable"}, status=503)
            return await handler(request)
        finally:
            self.concurrent -= 1

    @property
    def middleware(self) -> Callable[..., Awaitable[web.StreamResponse]]:
        """The network as an aiohttp middleware, for a server's application."""

        @web.middleware
        async def network(
            request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
        ) -> web.StreamResponse:
            return await self.answer(request, handler)

        return network




APP_COMBINATION = "S3"
TOKEN_COMBINATION = "S1"
SERVICE_PROVIDER = "Simulated service"


@dataclass(frozen=True)
class User:
    """A user of the simulated MitID, and the authenticators they have."""

    app: bool = True
    """Whether the user has the MitID app."""
    code_token: bool = False
    """Whether the user has a code token, which MitID follows with the password."""
    token_digits: str = "123456"
    """The digits the code token shows."""
    password: str = "simulated-password"


@dataclass
class _Authenticator:
    kind: str
    session_id: str = field(default_factory=lambda: secrets.token_hex(8))
    flow_key: str = field(default_factory=lambda: secrets.token_hex(16))
    eafe_hash: str = field(default_factory=lambda: secrets.token_hex(16))
    srp_salt: str = ""
    srp: CustomSRP = field(default_factory=CustomSRP)


@dataclass
class _Login:
    user: User = User(app=False)
    authenticator: _Authenticator | None = None
    ticket: str = field(default_factory=lambda: secrets.token_hex(8))
    polls: int = 0
    app_response: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    app_signature: bytes = field(default_factory=lambda: secrets.token_bytes(48))
    errors: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    approved: bool = False
    finalization_id: str = field(default_factory=lambda: secrets.token_hex(8))


async def _json(request: web.Request) -> dict[str, Any]:
    return cast(dict[str, Any], await request.json())


class SimulatedMitID:
    """A MitID on a local test server, with the users and app answers a test gives it.

    `users` are user IDs, each with the MitID app only, or each user ID's `User`. Use it as an
    async context manager; `url` is then the base URL to give the browser client.
    """

    BROKER_SECURITY_CONTEXT = "simulated-broker-context"
    REFERENCE_TEXT_HEADER = "Log in to"
    REFERENCE_TEXT_BODY = SERVICE_PROVIDER

    def __init__(self, users: Iterable[str] | Mapping[str, User] | None = None, network: Network | None = None) -> None:
        if users is None:
            users = {"parent"}
        self.users: dict[str, User] = (
            dict(cast(Mapping[str, User], users))
            if isinstance(users, Mapping)
            else {user_id: User() for user_id in users}
        )
        self.network = network or Network()
        self.client_hash = secrets.token_hex(32)
        self.app_answers = ["timeout", "channel_validation_tqr", "channel_verified", "OK"]
        """What the app's poll answers, one each poll; the last is repeated."""
        self.authorization_code = "simulated-authorization-code"
        self.logins: dict[str, _Login] = {}
        self._server: TestServer | None = None
        self.app = web.Application(middlewares=[self.network.middleware])
        core = "/mitid-core-client-backend"
        app = "/mitid-code-app-auth/v1/authenticator-sessions/web/{asid}"
        token = "/mitid-code-token-auth/v1/authenticator-sessions/{asid}"
        password = "/mitid-password-auth/v1/authenticator-sessions/{asid}"
        self.app.add_routes(
            [
                web.get(core + "/v1/authentication-sessions/{sid}", self._session),
                web.put(core + "/v1/authentication-sessions/{sid}", self._identify),
                web.post(core + "/v2/authentication-sessions/{sid}/next", self._next),
                web.put(core + "/v1/authentication-sessions/{fid}/finalization", self._finalize),
                web.post(app + "/init-auth", self._init_auth),
                web.post("/poll/{sid}", self._poll),
                web.post(app + "/init", self._app_init),
                web.post(app + "/prove", self._app_prove),
                web.post(app + "/verify", self._app_verify),
                web.post(token + "/codetoken-init", self._token_init),
                web.post(token + "/codetoken-prove", self._token_prove),
                web.post(password + "/init", self._password_init),
                web.post(password + "/password-prove", self._password_prove),
            ]
        )

    async def __aenter__(self) -> Self:
        self._server = TestServer(self.app)
        await self._server.start_server(access_log=None)
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if self._server is not None:
            await self._server.close()

    @property
    def url(self) -> str:
        """The base URL the simulated MitID answers at."""
        assert self._server is not None, "use the simulated MitID as an async context manager"
        return str(self._server.make_url("")).rstrip("/")

    def new_login(self) -> dict[str, Any]:
        """Start a login as NemLog-in does, and give the parameters (Aux) it hands the browser client."""
        session_id = secrets.token_hex(8)
        self.logins[session_id] = _Login()
        return {
            "coreClient": {"checksum": base64.b64encode(binascii.unhexlify(self.client_hash)).decode("ascii")},
            "parameters": {"authenticationSessionId": session_id},
        }

    def _login(self, request: web.Request, key: str = "sid") -> _Login:
        login = self.logins.get(request.match_info[key])
        if login is None:
            raise web.HTTPBadRequest(text='{"errorCode": "control.authentication_session_not_found"}')
        return login

    def _by_authenticator(self, request: web.Request, kind: str) -> tuple[str, _Login, _Authenticator]:
        for session_id, login in self.logins.items():
            authenticator = login.authenticator
            if (
                authenticator is not None
                and authenticator.kind == kind
                and authenticator.session_id == request.match_info["asid"]
            ):
                return session_id, login, authenticator
        raise web.HTTPNotFound()

    async def _session(self, request: web.Request) -> web.Response:
        self._login(request)
        return web.json_response(
            {
                "brokerSecurityContext": self.BROKER_SECURITY_CONTEXT,
                "serviceProviderName": SERVICE_PROVIDER,
                "referenceTextHeader": self.REFERENCE_TEXT_HEADER,
                "referenceTextBody": self.REFERENCE_TEXT_BODY,
            }
        )

    async def _identify(self, request: web.Request) -> web.Response:
        login = self._login(request)
        claim = str((await _json(request))["identityClaim"])
        if claim not in self.users:
            return web.json_response({"errorCode": "control.identity_not_found"}, status=400)
        login.user = self.users[claim]
        return web.json_response({})

    @staticmethod
    def _combinations(user: User) -> dict[str, str]:
        """The user's combinations, by ID, each with its first authenticator."""
        return {
            combination: kind
            for combination, kind, has in ((APP_COMBINATION, "APP", user.app), (TOKEN_COMBINATION, "TOKEN", user.code_token))
            if has
        }

    async def _next(self, request: web.Request) -> web.Response:
        login = self._login(request)
        if login.approved:
            return web.json_response({"errors": [], "nextSessionId": login.finalization_id})
        if login.errors:
            errors, login.errors = login.errors, []
            return web.json_response({"errors": errors})
        combination = str((await _json(request))["combinationId"])
        combinations = self._combinations(login.user)
        if combination:
            if combination not in combinations:
                return self._cannot_be_started()
            login.authenticator = _Authenticator(combinations[combination])
        elif login.authenticator is None:
            if not combinations:
                return self._cannot_be_started()
            login.authenticator = _Authenticator(next(iter(combinations.values())))
        authenticator = login.authenticator
        names = {APP_COMBINATION: ["MitID app"], TOKEN_COMBINATION: ["Code token", "Password"]}
        return web.json_response(
            {
                "errors": [],
                "nextAuthenticator": {
                    "authenticatorType": authenticator.kind,
                    "authenticatorSessionFlowKey": authenticator.flow_key,
                    "eafeHash": authenticator.eafe_hash,
                    "authenticatorSessionId": authenticator.session_id,
                },
                "combinations": [
                    {"id": combination, "combinationItems": [{"name": name} for name in names[combination]]}
                    for combination in combinations
                ],
            }
        )

    @staticmethod
    def _cannot_be_started() -> web.Response:
        return web.json_response(
            {
                "errors": [
                    {
                        "errorCode": "control.authenticator_cannot_be_started",
                        "userMessage": {"text": {"text": "Not available"}},
                    }
                ]
            }
        )

    async def _init_auth(self, request: web.Request) -> web.Response:
        session_id, login, _ = self._by_authenticator(request, "APP")
        return web.json_response({"pollUrl": f"{self.url}/poll/{session_id}", "ticket": login.ticket})

    async def _poll(self, request: web.Request) -> web.Response:
        login = self._login(request)
        if (await _json(request)).get("ticket") != login.ticket:
            return web.json_response({"status": "error"}, status=400)
        answer = self.app_answers[min(login.polls, len(self.app_answers) - 1)]
        login.polls += 1
        match answer:
            case "channel_validation_tqr" | "channel_validation_otp":
                return web.json_response({"status": answer, "channelBindingValue": "a1b2c3d4", "updateCount": login.polls})
            case "OK":
                return web.json_response(
                    {
                        "status": "OK",
                        "confirmation": True,
                        "payload": {
                            "response": base64.b64encode(login.app_response).decode("ascii"),
                            "responseSignature": base64.b64encode(login.app_signature).decode("ascii"),
                        },
                    }
                )
            case _:
                return web.json_response({"status": answer})

    @staticmethod
    async def _srp_init(request: web.Request, authenticator: _Authenticator, password: str) -> dict[str, Any]:
        """Answer the client's A with B, for the SRP password `password`, and agree the session key."""
        srp = authenticator.srp = CustomSRP()
        srp.SRPStage1()
        authenticator.srp_salt = secrets.token_hex(16)
        srp.big_a = hex_to_int(str((await _json(request))["randomA"]["value"]))
        exponent = hex_to_int(hashlib.sha256((authenticator.srp_salt + password).encode("ascii")).hexdigest())
        verifier = pow(srp.g, exponent, srp.n)
        secret_b = secrets.randbits(256)
        srp.big_b = (srp.computeLittleS() * verifier + pow(srp.g, secret_b, srp.n)) % srp.n
        premaster = pow(srp.big_a * pow(verifier, srp.computeU(), srp.n), secret_b, srp.n)
        srp.K_bits = hashlib.sha256(str(premaster).encode("utf-8")).digest()
        return {"srpSalt": {"value": authenticator.srp_salt}, "randomB": {"value": int_to_hex(srp.big_b)}}

    @staticmethod
    def _expected_m1(authenticator: _Authenticator) -> str:
        session = hashlib.sha256(authenticator.session_id.encode("utf-8")).hexdigest()
        return authenticator.srp.computeM1(session, authenticator.srp_salt)

    def _expected_flow_value_proof(self, authenticator: _Authenticator, prefix: str) -> str:
        def b64(text: str) -> str:
            return base64.b64encode(text.encode("utf8")).decode("ascii")

        context = hashlib.sha256(self.BROKER_SECURITY_CONTEXT.encode("utf8")).hexdigest()
        flow_values = (
            f"{authenticator.session_id},{authenticator.flow_key},{self.client_hash},{authenticator.eafe_hash},"
            f"{context},{b64(self.REFERENCE_TEXT_HEADER)},{b64(self.REFERENCE_TEXT_BODY)},{b64(SERVICE_PROVIDER)}"
        ).encode("utf-8")
        key = hashlib.sha256((prefix + bytes_to_hex(authenticator.srp.K_bits)).encode("utf8")).digest()
        return hmac.new(key, flow_values, hashlib.sha256).hexdigest()

    async def _app_init(self, request: web.Request) -> web.Response:
        _, login, authenticator = self._by_authenticator(request, "APP")
        password = hashlib.sha256(login.app_response + authenticator.flow_key.encode("utf8")).hexdigest()
        return web.json_response(await self._srp_init(request, authenticator, password))

    async def _app_prove(self, request: web.Request) -> web.Response:
        _, _, authenticator = self._by_authenticator(request, "APP")
        body = await _json(request)
        expected_m1 = self._expected_m1(authenticator)
        if (
            body["m1"]["value"] != expected_m1
            or body["flowValueProof"]["value"] != self._expected_flow_value_proof(authenticator, "flowValues")
        ):
            return web.json_response({"errorCode": "auth.codeapp.proof_invalid"}, status=400)
        srp = authenticator.srp
        m2 = hashlib.sha256(
            (str(srp.big_a) + str(int(expected_m1, 16)) + bytes_to_hex(srp.K_bits)).encode("utf-8")
        ).hexdigest()
        return web.json_response({"m2": {"value": m2}})

    async def _app_verify(self, request: web.Request) -> web.Response:
        _, login, authenticator = self._by_authenticator(request, "APP")
        encrypted = str((await _json(request))["encAuth"])
        signature = base64.b64decode(pad(base64.b64encode(login.app_signature).decode("ascii")))
        if AesDecryptWithKey(encrypted, authenticator.srp.K_bits) != signature:
            return web.json_response({"errorCode": "auth.codeapp.signature_invalid"}, status=400)
        login.approved = True
        return web.Response(status=204)

    async def _token_init(self, request: web.Request) -> web.Response:
        _, _, authenticator = self._by_authenticator(request, "TOKEN")
        password = bytes_to_hex(authenticator.flow_key.encode("utf-8"))
        return web.json_response(await self._srp_init(request, authenticator, password))

    async def _token_prove(self, request: web.Request) -> web.Response:
        _, login, authenticator = self._by_authenticator(request, "TOKEN")
        body = await _json(request)
        if body["m1"]["value"] != self._expected_m1(authenticator):
            return web.json_response({"errorCode": "auth.codetoken.proof_invalid"}, status=400)
        # The digits are proven only by the key of the flow value proof.
        expected = self._expected_flow_value_proof(authenticator, "OTP" + login.user.token_digits)
        if body["flowValueProof"]["value"] != expected:
            login.errors = [{"errorCode": "TOTP_INVALID"}]
        else:
            login.authenticator = _Authenticator("PASSWORD")
        return web.Response(status=204)

    async def _password_init(self, request: web.Request) -> web.Response:
        _, login, authenticator = self._by_authenticator(request, "PASSWORD")
        salt = secrets.token_bytes(16)
        password = hashlib.pbkdf2_hmac("sha256", login.user.password.encode("utf-8"), salt, 20000, 32).hex()
        answer = await self._srp_init(request, authenticator, password)
        return web.json_response({**answer, "pbkdf2Salt": {"value": salt.hex()}})

    async def _password_prove(self, request: web.Request) -> web.Response:
        _, login, authenticator = self._by_authenticator(request, "PASSWORD")
        body = await _json(request)
        # The password is proven only by the SRP proof M1.
        if body["m1"]["value"] != self._expected_m1(authenticator):
            login.errors = [{"errorCode": "PASSWORD_INVALID"}]
        elif body["flowValueProof"]["value"] != self._expected_flow_value_proof(authenticator, "flowValues"):
            return web.json_response({"errorCode": "auth.password.proof_invalid"}, status=400)
        else:
            login.approved = True
        return web.Response(status=204)

    async def _finalize(self, request: web.Request) -> web.Response:
        for login in self.logins.values():
            if login.approved and login.finalization_id == request.match_info["fid"]:
                return web.json_response({"authorizationCode": self.authorization_code})
        return web.json_response({"errorCode": "control.authentication_session_not_found"}, status=400)
