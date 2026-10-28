# mitid_connect

Log in through [MitID](https://www.mitid.dk) from Python: an unofficial implementation of MitID's
browser client. It authenticates with the MitID app - by QR code or one-time code - or with a
code token, and gives back the authorization code that the service being logged in to exchanges
for its own tokens.

```python
from mitid_connect import BrowserClient

client = BrowserClient(client_hash, authentication_session_id)
authenticators = client.identify_as_user_and_get_available_authenticators("username")
client.authenticate_with_app()            # approve in the MitID app
code = client.finalize_authentication_and_get_authorization_code()
```

`client_hash` and `authentication_session_id` come from the service's NemLog-in page;
`get_authentication_code` does all of the above from that page's parameters.

It is used by [aula_connect](https://github.com/HairingX/aula_connect) to log in to Aula.

## Origin and licence

It carries on MitID-BrowserClient by Hundter, under the MIT licence (`LICENSE`).
