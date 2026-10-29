# mitid_connect

Log in through [MitID](https://www.mitid.dk) from Python: an unofficial implementation of MitID's
browser client. It authenticates with the MitID app - by QR code or one-time code - or with a
code token, and gives back the authorization code that the service being logged in to exchanges
for its own tokens.

It is asynchronous, and runs on the [aiohttp](https://docs.aiohttp.org) session the caller gives
it - the session of the service's login flow, as MitID's steps share its cookies:

```python
import aiohttp
from mitid_connect import BrowserClient

async with aiohttp.ClientSession() as session:
    client = BrowserClient(session, client_hash, authentication_session_id)
    await client.start()
    authenticators = await client.identify_as_user_and_get_available_authenticators("username")
    await client.authenticate_with_app()  # approve in the MitID app
    code = await client.finalize_authentication_and_get_authorization_code()
```

`client_hash` and `authentication_session_id` come from the service's NemLog-in page;
`get_authentication_code` does all of the above from that page's parameters. While the app login
runs, `get_current_qr_codes()` gives the two QR codes to show in turn, and `status_message` how
far it has come.

`mitid_connect.testing.SimulatedMitID` is a MitID on a local test server, for tests. It answers
an app login as MitID does, and checks the client's proofs as MitID does. Its `Network` gives each
answer a latency, fixed or drawn from a range, and fails a share of them, for stress tests.

It is used by [aula_connect](https://github.com/HairingX/aula_connect) to log in to Aula.

## Origin and licence

It carries on MitID-BrowserClient by Hundter, under the MIT licence (`LICENSE`).
