# natdal-device

The device side of **natdal-id**, the account service behind every Natdal app: sign in once, stay
signed in. A device makes its own Ed25519 key pair — only the public half ever leaves it — joins an
account through one browser approval (or an enrollment token), and from then on asks for short
access tokens by signing a timestamp. Nothing expires on its own.

- `Identity` — the key pair, `token_request` (the signed body of `POST /v1/token`), save/load to an
  owner-only file. Where the secret lives is the app's choice (OS keychain on desktops).
- `Client` (feature `client`, on by default) — a blocking HTTP client for the whole flow. An app with
  its own HTTP stack turns it off and uses `Identity` and `peek` only.
- **One device per PC** — the natdal app holds the PC's device key and asks for a short token per app
  (`Identity::token_request_for`, `Client::access_token_for(audience)` → `(token, expires_at)`, one
  cache per app, one timestamp counter for all of them). Each app keeps its own key (its mesh
  identity) and registers it under the PC (`register_app_key`); an app's device from before is moved
  under the PC with `handoff` — its key lives on as the app's key. `peers_for(audience)` is that app's
  peers. A refusal for one app is `Refused::AudienceRemoved` (removed from that PC on the web; only the
  web adds it back) or `Refused::AudienceNotAllowed` — never `SignedOut`.
- `peek` — read a token's claims (`ent`, `until`) for display. Anything that unlocks a feature on a
  server verifies the signature with natdal-id's JWKS instead.

Nothing in this crate is secret: it holds no keys, endpoints or credentials. The protocol is
specified in natdal-id's design document.

© 2026 Natdal. All rights reserved.
