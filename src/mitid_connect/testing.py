"""A simulated MitID, for tests: it answers the browser client's app login as MitID does.

It checks what a real MitID checks of the client - the SRP proof, the flow value proof and the
app's signature, encrypted with the agreed key - so a test of a login exercises the protocol, not
only its requests. Only the app authenticator is simulated.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self, cast

from aiohttp import web
from aiohttp.test_utils import TestServer

from .srp import AesDecryptWithKey, CustomSRP, bytes_to_hex, hex_to_int, int_to_hex, pad

APP_COMBINATION = "S3"
SERVICE_PROVIDER = "Simulated service"


@dataclass
class _Login:
    user_id: str = ""
    authenticator_session_id: str = field(default_factory=lambda: secrets.token_hex(8))
    flow_key: str = field(default_factory=lambda: secrets.token_hex(16))
    eafe_hash: str = field(default_factory=lambda: secrets.token_hex(16))
    ticket: str = field(default_factory=lambda: secrets.token_hex(8))
    polls: int = 0
    app_response: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    app_signature: bytes = field(default_factory=lambda: secrets.token_bytes(48))
    srp_salt: str = field(default_factory=lambda: secrets.token_hex(16))
    srp: CustomSRP = field(default_factory=CustomSRP)
    big_a: int = 0
    big_b: int = 0
    key: bytes = b""
    approved: bool = False
    finalization_id: str = field(default_factory=lambda: secrets.token_hex(8))


class SimulatedMitID:
    """A MitID on a local test server, with the users and app answers a test gives it.

    Use it as an async context manager; `url` is then the base URL to give the browser client.
    """

    BROKER_SECURITY_CONTEXT = "simulated-broker-context"
    REFERENCE_TEXT_HEADER = "Log in to"
    REFERENCE_TEXT_BODY = SERVICE_PROVIDER

    def __init__(self, users: set[str] | None = None) -> None:
        self.users = users if users is not None else {"parent"}
        self.client_hash = secrets.token_hex(32)
        self.app_answers = ["timeout", "channel_validation_tqr", "channel_verified", "OK"]
        """What the app's poll answers, one each poll; the last is repeated."""
        self.authorization_code = "simulated-authorization-code"
        self.logins: dict[str, _Login] = {}
        self._server: TestServer | None = None
        self.app = web.Application()
        core = "/mitid-core-client-backend"
        app = "/mitid-code-app-auth/v1/authenticator-sessions/web/{asid}"
        self.app.add_routes(
            [
                web.get(core + "/v1/authentication-sessions/{sid}", self._session),
                web.put(core + "/v1/authentication-sessions/{sid}", self._identify),
                web.post(core + "/v2/authentication-sessions/{sid}/next", self._next),
                web.put(core + "/v1/authentication-sessions/{fid}/finalization", self._finalize),
                web.post(app + "/init-auth", self._init_auth),
                web.post("/poll/{sid}", self._poll),
                web.post(app + "/init", self._init),
                web.post(app + "/prove", self._prove),
                web.post(app + "/verify", self._verify),
            ]
        )

    async def __aenter__(self) -> Self:
        self._server = TestServer(self.app)
        await self._server.start_server()
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

    def _by_authenticator(self, request: web.Request) -> tuple[str, _Login]:
        for session_id, login in self.logins.items():
            if login.authenticator_session_id == request.match_info["asid"]:
                return session_id, login
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
        claim = str(cast(dict[str, Any], await request.json())["identityClaim"])
        if claim not in self.users:
            return web.json_response({"errorCode": "control.identity_not_found"}, status=400)
        login.user_id = claim
        return web.json_response({})

    async def _next(self, request: web.Request) -> web.Response:
        login = self._login(request)
        if login.approved:
            return web.json_response({"errors": [], "nextSessionId": login.finalization_id})
        combination = str(cast(dict[str, Any], await request.json())["combinationId"])
        if combination not in ("", APP_COMBINATION):
            return web.json_response(
                {"errors": [{"errorCode": "control.authenticator_cannot_be_started", "userMessage": {"text": {"text": "Not available"}}}]}
            )
        return web.json_response(
            {
                "errors": [],
                "nextAuthenticator": {
                    "authenticatorType": "APP",
                    "authenticatorSessionFlowKey": login.flow_key,
                    "eafeHash": login.eafe_hash,
                    "authenticatorSessionId": login.authenticator_session_id,
                },
                "combinations": [{"id": APP_COMBINATION, "combinationItems": [{"name": "MitID app"}]}],
            }
        )

    async def _init_auth(self, request: web.Request) -> web.Response:
        session_id, login = self._by_authenticator(request)
        return web.json_response({"pollUrl": f"{self.url}/poll/{session_id}", "ticket": login.ticket})

    async def _poll(self, request: web.Request) -> web.Response:
        login = self._login(request)
        if cast(dict[str, Any], await request.json()).get("ticket") != login.ticket:
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

    def _verifier_exponent(self, login: _Login) -> int:
        password = hashlib.sha256(login.app_response + login.flow_key.encode("utf8")).hexdigest()
        return hex_to_int(hashlib.sha256((login.srp_salt + password).encode("ascii")).hexdigest())

    async def _init(self, request: web.Request) -> web.Response:
        _, login = self._by_authenticator(request)
        srp = login.srp
        srp.SRPStage1()
        login.big_a = hex_to_int(str(cast(dict[str, Any], await request.json())["randomA"]["value"]))
        verifier = pow(srp.g, self._verifier_exponent(login), srp.n)
        secret_b = secrets.randbits(256)
        login.big_b = (srp.computeLittleS() * verifier + pow(srp.g, secret_b, srp.n)) % srp.n
        srp.big_a, srp.big_b = login.big_a, login.big_b
        scrambler = srp.computeU()
        premaster = pow(login.big_a * pow(verifier, scrambler, srp.n), secret_b, srp.n)
        login.key = hashlib.sha256(str(premaster).encode("utf-8")).digest()
        return web.json_response({"srpSalt": {"value": login.srp_salt}, "randomB": {"value": int_to_hex(login.big_b)}})

    def _flow_values(self, login: _Login) -> bytes:
        def b64(text: str) -> str:
            return base64.b64encode(text.encode("utf8")).decode("ascii")

        context = hashlib.sha256(self.BROKER_SECURITY_CONTEXT.encode("utf8")).hexdigest()
        return (
            f"{login.authenticator_session_id},{login.flow_key},{self.client_hash},{login.eafe_hash},{context},"
            f"{b64(self.REFERENCE_TEXT_HEADER)},{b64(self.REFERENCE_TEXT_BODY)},{b64(SERVICE_PROVIDER)}"
        ).encode("utf-8")

    async def _prove(self, request: web.Request) -> web.Response:
        _, login = self._by_authenticator(request)
        body = cast(dict[str, Any], await request.json())
        srp = login.srp
        srp.K_bits = login.key
        expected_m1 = srp.computeM1(
            hashlib.sha256(login.authenticator_session_id.encode("utf-8")).hexdigest(), login.srp_salt
        )
        proof_key = hashlib.sha256(("flowValues" + bytes_to_hex(login.key)).encode("utf8")).digest()
        expected_proof = hmac.new(proof_key, self._flow_values(login), hashlib.sha256).hexdigest()
        if body["m1"]["value"] != expected_m1 or body["flowValueProof"]["value"] != expected_proof:
            return web.json_response({"errorCode": "auth.codeapp.proof_invalid"}, status=400)
        m2 = hashlib.sha256(
            (str(login.big_a) + str(int(expected_m1, 16)) + bytes_to_hex(login.key)).encode("utf-8")
        ).hexdigest()
        return web.json_response({"m2": {"value": m2}})

    async def _verify(self, request: web.Request) -> web.Response:
        _, login = self._by_authenticator(request)
        encrypted = str(cast(dict[str, Any], await request.json())["encAuth"])
        signature = base64.b64decode(pad(base64.b64encode(login.app_signature).decode("ascii")))
        if AesDecryptWithKey(encrypted, login.key) != signature:
            return web.json_response({"errorCode": "auth.codeapp.signature_invalid"}, status=400)
        login.approved = True
        return web.Response(status=204)

    async def _finalize(self, request: web.Request) -> web.Response:
        for login in self.logins.values():
            if login.approved and login.finalization_id == request.match_info["fid"]:
                return web.json_response({"authorizationCode": self.authorization_code})
        return web.json_response({"errorCode": "control.authentication_session_not_found"}, status=400)
