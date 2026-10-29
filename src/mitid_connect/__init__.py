"""Log in through MitID from Python: an unofficial implementation of MitID's browser client.

It authenticates with the MitID app (QR code or one-time code) or a code token, and gives back
the authorization code the service being logged in to exchanges for its own tokens. It is
asynchronous, and runs on the aiohttp session the caller gives it.
"""

from importlib.metadata import PackageNotFoundError, version

from .browser_client import BrowserClient, MitIDError
from .helpers import (
    choose_between_multiple_identitites,
    generate_nem_login_parameters,
    get_authentication_code,
)
from .srp import CustomSRP

try:
    __version__ = version("mitid_connect")
except PackageNotFoundError:  # pragma: no cover - only in a checkout that is not installed
    __version__ = "0.0.0"

__all__ = [
    "BrowserClient",
    "CustomSRP",
    "MitIDError",
    "__version__",
    "choose_between_multiple_identitites",
    "generate_nem_login_parameters",
    "get_authentication_code",
]
