"""MitID's browser client: identifies the user, runs an authenticator, and gives the code."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Mapping
from typing import Any, cast

import aiohttp
import qrcode

from .srp import CustomSRP, bytes_to_hex, hex_to_bytes, pad

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
"""Seconds a single request to MitID may take."""

MITID_URL = "https://www.mitid.dk"


class MitIDError(Exception):
    """MitID refused a step of the login, or answered it in a way the client does not know."""


class BrowserClient:
    """One MitID login, as MitID's own browser client runs it.

    The session's cookies are the login's: it must be the session the service's login flow uses.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        client_hash: str,
        authentication_session_id: str,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        base_url: str = MITID_URL,
    ) -> None:
        self.session = session
        self.client_hash = client_hash
        self.authentication_session_id = authentication_session_id
        self.headers = dict(headers or {})
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.base_url = base_url
        self.status_message = "Starting the MitID login"
        self.qr1: qrcode.QRCode[Any] | None = None
        self.qr2: qrcode.QRCode[Any] | None = None
        self.user_id = ""
        self.broker_security_context = ""
        self.service_provider_name = ""
        self.reference_text_header = ""
        self.reference_text_body = ""
        self.current_authenticator_type = ""
        self.current_authenticator_session_flow_key = ""
        self.current_authenticator_eafe_hash = ""
        self.current_authenticator_session_id = ""
        self.finalization_authentication_session_id = ""
        self.poll_url = ""
        self.ticket = ""
        self.otp_code: str | None = None
        self.auth_response = ""
        self.auth_response_signature = ""

    async def _call(
        self, method: str, url: str, payload: Mapping[str, Any] | None = None, *, send_json: bool = True
    ) -> tuple[int, Any]:
        """Send one request, and give its status and its JSON answer, None when it has none."""
        if not url.startswith("http"):
            url = self.base_url + url
        async with self.session.request(
            method,
            url,
            json=payload if send_json else None,
            headers=self.headers,
            timeout=self.timeout,
        ) as response:
            body = await response.read()
            status = response.status
        if not body:
            return status, None
        try:
            return status, json.loads(body)
        except ValueError:
            return status, None

    @staticmethod
    def _failure(step: str, status: int, data: Any) -> MitIDError:
        code = cast(dict[str, Any], data).get("errorCode") if isinstance(data, dict) else None
        return MitIDError(f"{step} failed: HTTP {status}{f' ({code})' if code else ''}")

    async def start(self) -> None:
        """Read the login session MitID made for the service, which every later step proves."""
        status, data = await self._call(
            "GET", f"/mitid-core-client-backend/v1/authentication-sessions/{self.authentication_session_id}"
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Reading the authentication session", status, data)
        session = cast(dict[str, Any], data)
        self.broker_security_context = str(session["brokerSecurityContext"])
        self.service_provider_name = str(session["serviceProviderName"])
        self.reference_text_header = str(session["referenceTextHeader"])
        self.reference_text_body = str(session["referenceTextBody"])
        self.status_message = f"Beginning login session for {self.service_provider_name}"
        _LOGGER.debug("Beginning login session for %s", self.service_provider_name)

    def get_current_qr_codes(self) -> tuple[qrcode.QRCode[Any], qrcode.QRCode[Any]] | None:
        """The two QR codes MitID asks to scan, in turn, None while it asks for none."""
        if self.qr1 is None or self.qr2 is None:
            return None
        return self.qr1, self.qr2

    def _set_qr_codes(self, data: Mapping[str, Any]) -> None:
        channel_binding = str(data["channelBindingValue"])
        half = len(channel_binding) // 2
        codes: list[qrcode.QRCode[Any]] = []
        for part, value in ((1, channel_binding[:half]), (2, channel_binding[half:])):
            code: qrcode.QRCode[Any] = qrcode.QRCode(border=1)
            code.add_data(
                json.dumps({"v": 1, "p": part, "t": 2, "h": value, "uc": data["updateCount"]}, separators=(",", ":"))
            )
            code.make()
            codes.append(code)
        self.qr1, self.qr2 = codes

    @staticmethod
    def _authenticator_name(combination_id: str) -> str:
        match combination_id:
            case "S4" | "S3" | "L2":
                return "APP"
            case "S1":
                return "TOKEN"
            case _:
                raise MitIDError(f"No such combination ID ({combination_id})")

    @staticmethod
    def _combination_id(authenticator_name: str) -> str:
        match authenticator_name:
            case "APP":
                return "S3"
            case "TOKEN":
                return "S1"
            case _:
                raise MitIDError(f"No such authenticator name ({authenticator_name})")

    def _take_next_authenticator(self, data: Mapping[str, Any]) -> None:
        nxt = cast(dict[str, Any], data["nextAuthenticator"])
        self.current_authenticator_type = str(nxt["authenticatorType"])
        self.current_authenticator_session_flow_key = str(nxt["authenticatorSessionFlowKey"])
        self.current_authenticator_eafe_hash = str(nxt["eafeHash"])
        self.current_authenticator_session_id = str(nxt["authenticatorSessionId"])

    @staticmethod
    def _cannot_start(data: Mapping[str, Any]) -> None:
        errors = cast(list[dict[str, Any]], data.get("errors") or [])
        if errors and errors[0].get("errorCode") == "control.authenticator_cannot_be_started":
            raise MitIDError(str(errors[0]["userMessage"]["text"]["text"]))

    async def identify_as_user_and_get_available_authenticators(self, user_id: str) -> dict[str, str]:
        """Say who logs in, and give the authenticators the user has, by name."""
        self.user_id = user_id
        status, data = await self._call(
            "PUT",
            f"/mitid-core-client-backend/v1/authentication-sessions/{self.authentication_session_id}",
            {"identityClaim": user_id},
        )
        if status != 200:
            code = cast(dict[str, Any], data).get("errorCode") if isinstance(data, dict) else None
            if code == "control.identity_not_found":
                raise MitIDError("MitID knows no user with that user ID")
            raise self._failure("Identifying the user", status, data)

        status, data = await self._call(
            "POST",
            f"/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next",
            {"combinationId": ""},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Reading the user's authenticators", status, data)
        answer = cast(dict[str, Any], data)
        self._cannot_start(answer)
        self._take_next_authenticator(answer)
        return {
            self._authenticator_name(str(combination["id"])): str(combination["combinationItems"][0]["name"])
            for combination in cast(list[dict[str, Any]], answer["combinations"])
        }

    def _create_flow_value_proof(self) -> bytes:
        hashed_broker_security_context = hashlib.sha256(self.broker_security_context.encode("utf8")).hexdigest()

        def b64(text: str) -> str:
            return base64.b64encode(text.encode("utf8")).decode("ascii")

        return (
            f"{self.current_authenticator_session_id},{self.current_authenticator_session_flow_key},"
            f"{self.client_hash},{self.current_authenticator_eafe_hash},{hashed_broker_security_context},"
            f"{b64(self.reference_text_header)},{b64(self.reference_text_body)},{b64(self.service_provider_name)}"
        ).encode("utf-8")

    async def _select_authenticator(self, authenticator_type: str) -> None:
        if authenticator_type == self.current_authenticator_type:
            return
        status, data = await self._call(
            "POST",
            f"/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next",
            {"combinationId": self._combination_id(authenticator_type)},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Choosing the authenticator", status, data)
        answer = cast(dict[str, Any], data)
        self._cannot_start(answer)
        self._take_next_authenticator(answer)
        if self.current_authenticator_type != authenticator_type:
            raise MitIDError(
                f"Was not able to choose the desired authenticator ({authenticator_type}), "
                f"instead we received ({self.current_authenticator_type})"
            )

    async def _next(self, step: str) -> dict[str, Any]:
        status, data = await self._call(
            "POST",
            f"/mitid-core-client-backend/v2/authentication-sessions/{self.authentication_session_id}/next",
            {"combinationId": ""},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure(step, status, data)
        return cast(dict[str, Any], data)

    async def authenticate_with_token(self, token_digits: str) -> None:
        """Prove the code token's current digits; the password is next."""
        await self._select_authenticator("TOKEN")
        timer_1 = time.time()
        srp = CustomSRP()
        random_a = srp.SRPStage1()
        timer_1 = time.time() - timer_1

        status, data = await self._call(
            "POST",
            f"/mitid-code-token-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/codetoken-init",
            {"randomA": {"value": random_a}},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Starting the code token", status, data)
        init = cast(dict[str, Any], data)

        timer_2 = time.time()
        m1 = srp.SRPStage3(
            str(init["srpSalt"]["value"]),
            str(init["randomB"]["value"]),
            bytes_to_hex(self.current_authenticator_session_flow_key.encode("utf-8")),
            self.current_authenticator_session_id,
        )
        key = hashlib.sha256(("OTP" + token_digits + bytes_to_hex(srp.K_bits)).encode("utf8")).digest()
        flow_value_proof = hmac.new(key, self._create_flow_value_proof(), hashlib.sha256).hexdigest()
        timer_2 = time.time() - timer_2

        status, data = await self._call(
            "POST",
            f"/mitid-code-token-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/codetoken-prove",
            {
                "m1": {"value": m1},
                "flowValueProof": {"value": flow_value_proof},
                "frontEndProcessingTime": int((timer_1 + timer_2) * 1000),
            },
        )
        if status != 204:
            raise self._failure("Proving the code token", status, data)

        answer = await self._next("Accepting the code token")
        errors = cast(list[dict[str, Any]], answer.get("errors") or [])
        if errors and errors[0].get("errorCode") == "TOTP_INVALID":
            raise MitIDError("MitID did not accept the code token's digits")
        nxt = answer.get("nextAuthenticator")
        if not isinstance(nxt, dict) or cast(dict[str, Any], nxt).get("authenticatorType") != "PASSWORD":
            raise MitIDError("MitID asked for something else than the password after the code token")
        self._take_next_authenticator(answer)

    async def authenticate_with_password(self, password: str) -> None:
        """Prove the password, after the code token."""
        if self.current_authenticator_type != "PASSWORD":
            raise MitIDError(
                "You cannot authenticate with password before completing authentication with token code, "
                f"the current authenticator type was ({self.current_authenticator_type})"
            )
        timer_1 = time.time()
        srp = CustomSRP()
        random_a = srp.SRPStage1()
        timer_1 = time.time() - timer_1

        status, data = await self._call(
            "POST",
            f"/mitid-password-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/init",
            {"randomA": {"value": random_a}},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Starting the password", status, data)
        init = cast(dict[str, Any], data)

        timer_2 = time.time()
        hashed = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), hex_to_bytes(str(init["pbkdf2Salt"]["value"])), 20000, 32
        ).hex()
        m1 = srp.SRPStage3(
            str(init["srpSalt"]["value"]), str(init["randomB"]["value"]), hashed, self.current_authenticator_session_id
        )
        key = hashlib.sha256(("flowValues" + bytes_to_hex(srp.K_bits)).encode("utf8")).digest()
        flow_value_proof = hmac.new(key, self._create_flow_value_proof(), hashlib.sha256).hexdigest()
        timer_2 = time.time() - timer_2

        status, data = await self._call(
            "POST",
            f"/mitid-password-auth/v1/authenticator-sessions/{self.current_authenticator_session_id}/password-prove",
            {
                "m1": {"value": m1},
                "flowValueProof": {"value": flow_value_proof},
                "frontEndProcessingTime": int((timer_1 + timer_2) * 1000),
            },
        )
        if status != 204:
            raise self._failure("Proving the password", status, data)

        answer = await self._next("Accepting the password")
        errors = cast(list[dict[str, Any]], answer.get("errors") or [])
        if errors:
            raise MitIDError(f"MitID did not accept the password ({errors[0].get('errorCode')})")
        self.finalization_authentication_session_id = str(answer["nextSessionId"])
        self.status_message = "Password accepted, finalizing authentication"

    async def _start_app(self) -> None:
        await self._select_authenticator("APP")
        status, data = await self._call(
            "POST",
            f"/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}/init-auth",
            {},
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Requesting the app login", status, data)
        init = cast(dict[str, Any], data)
        if init.get("errorCode") == "auth.codeapp.authentication.parallel_sessions_detected":
            raise MitIDError("Parallel app sessions detected. Please wait a few minutes before trying again.")
        self.poll_url = str(init["pollUrl"])
        self.ticket = str(init["ticket"])
        self.otp_code = None
        self.status_message = "Login request has been made, open your MitID app now"

    async def start_app_authentication(self) -> dict[str, str]:
        """Ask the MitID app to approve, and give where to poll for its answer."""
        await self._start_app()
        return {"poll_url": self.poll_url, "ticket": self.ticket}

    async def poll_app_authentication_status(self) -> dict[str, Any]:
        """Ask once how far the app's approval has come.

        Returns the step: waiting, otp_ready (with the code to type in the app), qr_ready (the QR
        codes are set), verified, completed or error, and a message.
        """
        if not self.poll_url:
            raise MitIDError("Authentication not started - call start_app_authentication() first")
        status, data = await self._call("POST", self.poll_url, {"ticket": self.ticket})
        if status != 200 or not isinstance(data, dict):
            return {"status": "error", "message": "Poll request failed"}
        poll = cast(dict[str, Any], data)
        match poll.get("status"):
            case "timeout":
                return {"status": "waiting", "message": "Waiting for response..."}
            case "channel_validation_otp":
                self.otp_code = str(poll["channelBindingValue"])
                self.status_message = f"Please use the following OTP code in the app: {self.otp_code}"
                return {"status": "otp_ready", "message": self.status_message, "otp_code": self.otp_code}
            case "channel_validation_tqr":
                self._set_qr_codes(poll)
                self.status_message = "Login request has been made, open your MitID app now"
                return {"status": "qr_ready", "message": self.status_message}
            case "channel_verified":
                self.qr1 = self.qr2 = None
                self.status_message = "The OTP/QR code has been verified, now waiting user to approve login"
                return {"status": "verified", "message": self.status_message}
            case "OK" if poll.get("confirmation") is True:
                payload = cast(dict[str, Any], poll["payload"])
                self.auth_response = str(payload["response"])
                self.auth_response_signature = str(payload["responseSignature"])
                return {"status": "completed", "message": "Authentication successful"}
            case _:
                self.qr1 = self.qr2 = None
                return {"status": "error", "message": "Authentication was not accepted"}

    async def complete_app_authentication(self) -> str:
        """Prove the app's approval to MitID, and give the session to finalize."""
        if not self.auth_response:
            raise MitIDError("Authentication not completed - poll until status is 'completed'")
        timer_1 = time.time()
        srp = CustomSRP()
        random_a = srp.SRPStage1()
        timer_1 = time.time() - timer_1

        session_url = f"/mitid-code-app-auth/v1/authenticator-sessions/web/{self.current_authenticator_session_id}"
        status, data = await self._call("POST", f"{session_url}/init", {"randomA": {"value": random_a}})
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Starting the app's proof", status, data)
        init = cast(dict[str, Any], data)

        timer_2 = time.time()
        password = hashlib.sha256(
            base64.b64decode(self.auth_response) + self.current_authenticator_session_flow_key.encode("utf8")
        ).hexdigest()
        m1 = srp.SRPStage3(
            str(init["srpSalt"]["value"]), str(init["randomB"]["value"]), password, self.current_authenticator_session_id
        )
        key = hashlib.sha256(("flowValues" + bytes_to_hex(srp.K_bits)).encode("utf8")).digest()
        flow_value_proof = hmac.new(key, self._create_flow_value_proof(), hashlib.sha256).hexdigest()
        timer_2 = time.time() - timer_2

        status, data = await self._call(
            "POST", f"{session_url}/prove", {"m1": {"value": m1}, "flowValueProof": {"value": flow_value_proof}}
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Proving the app's approval", status, data)
        timer_3 = time.time()
        if not srp.SRPStage5(str(cast(dict[str, Any], data)["m2"]["value"])):
            raise MitIDError("m2 could not be validated during proving of app response")
        auth_enc = base64.b64encode(srp.AuthEnc(base64.b64decode(pad(self.auth_response_signature)))).decode("ascii")
        timer_3 = time.time() - timer_3

        status, data = await self._call(
            "POST",
            f"{session_url}/verify",
            {"encAuth": auth_enc, "frontEndProcessingTime": int((timer_1 + timer_2 + timer_3) * 1000)},
        )
        if status != 204:
            raise self._failure("Verifying the app's signature", status, data)

        answer = await self._next("Accepting the app login")
        if answer.get("errors"):
            raise MitIDError("Could not prove the app login. Please try again.")
        self.finalization_authentication_session_id = str(answer["nextSessionId"])
        self.status_message = "App login was accepted, finalizing authentication"
        return self.finalization_authentication_session_id

    async def authenticate_with_app(self) -> None:
        """Ask the MitID app to approve, wait until it has, and prove its approval."""
        await self._start_app()
        while True:
            result = await self.poll_app_authentication_status()
            match result["status"]:
                case "waiting" | "otp_ready" | "qr_ready" | "verified":
                    continue
                case "completed":
                    break
                case _:
                    raise MitIDError("Login request was not accepted")
        await self.complete_app_authentication()

    async def finalize_authentication_and_get_authorization_code(self) -> str:
        """Finish the login, and give the authorization code the service exchanges for its tokens."""
        if not self.finalization_authentication_session_id:
            raise MitIDError("No finalization session ID set, make sure you have completed an authentication flow.")
        status, data = await self._call(
            "PUT",
            f"/mitid-core-client-backend/v1/authentication-sessions/{self.finalization_authentication_session_id}/finalization",
            send_json=False,
        )
        if status != 200 or not isinstance(data, dict):
            raise self._failure("Finalizing the login", status, data)
        return str(cast(dict[str, Any], data)["authorizationCode"])
