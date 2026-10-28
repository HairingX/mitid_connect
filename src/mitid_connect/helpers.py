"""Ready-made steps of a NemLog-in login flow around the MitID browser client."""

import binascii, base64, hashlib, logging
from typing import Any

from Cryptodome import Random
from requests import Response, Session
from .browser_client import BrowserClient
from bs4 import BeautifulSoup

_LOGGER = logging.getLogger(__name__)

def get_authentication_code(
    session: Session, aux: dict[str, Any], method: str, user_id: str, password: str | None
) -> str:
    """Log `user_id` in with the MitID app, from NemLog-in's parameters `aux`, and give the code.

    Raises:
        NotImplementedError: `method` is "TOKEN", which needs the token's digits.
        Exception: the method is unknown, or not one the user has.
    """
    client_hash = binascii.hexlify(base64.b64decode(aux["coreClient"]["checksum"])).decode('ascii')
    authentication_session_id = aux["parameters"]["authenticationSessionId"]

    MitIDClient = BrowserClient(client_hash, authentication_session_id, session)
    available_authenticators = MitIDClient.identify_as_user_and_get_available_authenticators(user_id)

    _LOGGER.debug(f"Available authenticator: {available_authenticators}")

    if method == "TOKEN" and "TOKEN" in available_authenticators:
        if not password:
            raise ValueError("Password is required for TOKEN authentication")
        # Token digits must be provided via the caller, not via interactive input
        raise NotImplementedError(
            "TOKEN authentication requires token_digits parameter - interactive input not supported"
        )
    elif method == "APP" and "APP" in available_authenticators:
        MitIDClient.authenticate_with_app()
    elif method == "TOKEN" and "TOKEN" not in available_authenticators:
        raise Exception(f"Token authentication method chosen but not available for MitID user")
    elif method == "APP" and "APP" not in available_authenticators:    
        raise Exception(f"App authentication method chosen but not available for MitID user")
    else:
        raise Exception(f"Unknown authenticator method: {method}")

    authorization_code = MitIDClient.finalize_authentication_and_get_authorization_code()
    return authorization_code

def choose_between_multiple_identitites(
    session: Session, request: Response, soup: BeautifulSoup, identity_index: int = 0
) -> tuple[Response, BeautifulSoup]:
    """Choose between multiple identities.

    Args:
        session: requests session
        request: current request object
        soup: BeautifulSoup parsed response
        identity_index: zero-based index of the identity to select (default: 0, first identity)

    Returns:
        Tuple of (request, soup) after identity selection
    """
    data = {}
    for soup_input in soup.form.select("input"):
        try:
            data[soup_input["name"]] = soup_input["value"]
        except KeyError:
            data[soup_input.get("name", "")] = ""
    login_options = soup.select("div.list-link-box")
    _LOGGER.info('Multiple identities available:')
    for i, login_option in enumerate(login_options):
        _LOGGER.info(f'{i+1}: {login_option.select_one("div.list-link-text").string}')

    if identity_index < 0 or identity_index >= len(login_options):
        raise ValueError(f"Identity index {identity_index} out of range (0-{len(login_options)-1})")

    selected_option = login_options[identity_index].a["data-loginoptions"]
    data["ChosenOptionJson"] = selected_option
    _LOGGER.info(f'Selected identity {identity_index + 1}')

    request = session.post(request.url, data=data)
    soup = BeautifulSoup(request.text, "xml")
    return request, soup

def __generate_random_string():
    return binascii.hexlify(Random.new().read(28)).decode("utf-8")

def __generate_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")

def generate_nem_login_parameters() -> tuple[str, str, str, str]:
    """A fresh state, nonce, PKCE code verifier and its S256 code challenge for NemLog-in."""
    nem_login_state = __generate_random_string()
    nem_login_nonce = __generate_random_string()
    nem_login_code_verifier = __generate_random_string()
    nem_login_code_challenge = __generate_challenge(nem_login_code_verifier)

    return nem_login_state, nem_login_nonce, nem_login_code_verifier, nem_login_code_challenge
