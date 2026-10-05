# natdal-device

The device side of **natdal-id**, the account service behind every Natdal app: sign in once, stay
signed in. A device makes its own Ed25519 key pair — only the public half ever leaves it — joins an
account through one browser approval (or an enrollment token), and from then on asks for short
access tokens by signing a timestamp. Nothing expires on its own.

- `Identity` — the key pair, `token_request` (the signed body of `POST /v1/token`), save/load to an
  owner-only file. Where the secret lives is the app's choice (OS keychain on desktops).
- `Client` (feature `client`, on by default) — a blocking HTTP client for the whole flow. An app with
  its own HTTP stack turns it off and uses `Identity` and `peek` only.
- `peek` — read a token's claims (`ent`, `until`) for display. Anything that unlocks a feature on a
  server verifies the signature with natdal-id's JWKS instead.

Nothing in this crate is secret: it holds no keys, endpoints or credentials. The protocol is
specified in natdal-id's design document.

© 2026 Natdal. All rights reserved.
