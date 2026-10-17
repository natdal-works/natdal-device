//! natdal-device — what a Natdal app links to sign in once and stay signed in.
//!
//! The device makes its own Ed25519 key pair; only the public half ever leaves it. After one
//! approval in a browser (or one enrollment token) the device asks for short access tokens by
//! signing a timestamp — no password, no refresh token, nothing that expires on its own.
//! Protocol: natdal-id's design (`natdal-works/natdal-platform`, `docs/design.md`).
//!
//! Where the secret lives is the app's choice: [`Identity::secret`] hands out the 32 bytes for the
//! OS keychain; [`Identity::save`] writes a 0600 file for servers.

#[cfg(feature = "client")]
use std::sync::Mutex;

#[cfg(feature = "client")]
use anyhow::bail;
use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

/// The device's key and, once joined, its id.
pub struct Identity {
    key: SigningKey,
    pub device_id: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    device_id: Option<i64>,
    secret: String,
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_secret(rand::random::<[u8; 32]>(), None)
    }

    pub fn from_secret(secret: [u8; 32], device_id: Option<i64>) -> Self {
        Self { key: SigningKey::from_bytes(&secret), device_id }
    }

    /// The 32 secret bytes — for the OS keychain. Never send them anywhere.
    pub fn secret(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    /// Write to a file only the owner can read (servers; desktops use the keychain).
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let body = serde_json::to_vec(&Stored { device_id: self.device_id, secret: hex::encode(self.secret()) })?;
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?.write_all(&body)?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let s: Stored = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)?;
        let secret: [u8; 32] = hex::decode(&s.secret)?.try_into().map_err(|_| anyhow::anyhow!("secret must be 32 bytes"))?;
        Ok(Self::from_secret(secret, s.device_id))
    }

    fn sign(&self, msg: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.sign(msg.as_bytes()).to_bytes())
    }

    /// The body of `POST /v1/token` for this device at `ts` (milliseconds) — for an app that makes
    /// the call with its own HTTP client. `ts` must grow with every request.
    pub fn token_request(&self, device_id: i64, ts: i64) -> serde_json::Value {
        let sig = self.sign(&token_message(device_id, ts));
        serde_json::json!({ "device_id": device_id, "ts": ts, "sig": sig })
    }

    /// The body of `POST /v1/token` asking for a token **for one app** (`audience`, e.g.
    /// `guildlings`). A platform device (natdal) may ask for any app's audience; a device of one app
    /// only for its own. `ts` must grow with every request, across audiences — they share one
    /// counter.
    pub fn token_request_for(&self, device_id: i64, ts: i64, audience: &str) -> serde_json::Value {
        let sig = self.sign(&token_message_for(device_id, ts, audience));
        serde_json::json!({ "device_id": device_id, "ts": ts, "audience": audience, "sig": sig })
    }

    /// The body of `POST /v1/app-keys`, signed by **this** key — an app's own key (its mesh
    /// identity), proving the app holds it — to register it under the platform device
    /// `device_id` for `audience`.
    pub fn app_key_request(&self, device_id: i64, audience: &str, ts: i64) -> serde_json::Value {
        let sig = self.sign(&app_key_message(device_id, audience, ts));
        serde_json::json!({ "pubkey": self.public_hex(), "ts": ts, "sig": sig })
    }

    /// The body of `POST /v1/devices/handoff`, signed by **this** key — the key of an app's own
    /// device from before the platform (`old_device_id`) — moving it under the platform device
    /// `new_device_id`, where it lives on as that app's key.
    pub fn handoff_request(&self, old_device_id: i64, new_device_id: i64, ts: i64) -> serde_json::Value {
        let sig = self.sign(&handoff_message(old_device_id, new_device_id, ts));
        serde_json::json!({ "old_device_id": old_device_id, "ts": ts, "sig": sig })
    }
}

/// The message a device signs to ask for an access token.
pub fn token_message(device_id: i64, ts: i64) -> String {
    format!("natdal-token-v1\n{device_id}\n{ts}")
}

/// The message a device signs to ask for an access token for one app (`audience`).
pub fn token_message_for(device_id: i64, ts: i64, audience: &str) -> String {
    format!("natdal-token-v2\n{device_id}\n{ts}\n{audience}")
}

/// The message an app's key signs to be registered under the platform device `device_id`.
pub fn app_key_message(device_id: i64, audience: &str, ts: i64) -> String {
    format!("natdal-app-key-v1\n{device_id}\n{audience}\n{ts}")
}

/// The message an app's old device key signs to hand itself over to the platform device `new_device_id`.
pub fn handoff_message(old_device_id: i64, new_device_id: i64, ts: i64) -> String {
    format!("natdal-handoff-v1\n{old_device_id}\n{new_device_id}\n{ts}")
}

/// What to show the person: open `url` (desktop) or print it with `code` (ssh).
#[derive(Debug, Clone, Deserialize)]
pub struct Started {
    pub url: String,
    pub code: String,
    pub poll: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Poll {
    Pending,
    Expired,
    Done { device_id: i64 },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Access {
    pub access_token: String,
    pub expires_in: i64,
}

#[cfg(feature = "client")]
/// Why a call was refused — so an app can tell "sign in again" from "try later".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refused {
    /// The device was removed from the account, or its key is unknown: sign in again.
    #[error("this device is no longer signed in")]
    SignedOut,
    #[error("the server answered {0}")]
    Status(u16),
    /// This PC was removed from that app on the web (the account page's "Remove from …"): only that
    /// app is signed out — the device stays signed in, and only the web's "Add back" returns it.
    /// Never a reason to sign the device out or delete its key.
    #[error("this PC was removed from that app on the web")]
    AudienceRemoved,
    /// This device may not ask for that app (a device of one app asks only for its own). Not a
    /// sign-out either.
    #[error("this device may not ask for that app")]
    AudienceNotAllowed,
    /// natdal-id does not know that app (a 400 that is not the clock): a caller's bug or a server
    /// without that app yet. Not a sign-out, and not the clock either.
    #[error("natdal-id does not know that app")]
    UnknownAudience,
}

#[cfg(feature = "client")]
pub struct Client {
    base: String,
    product: String,
    agent: ureq::Agent,
    cache: Mutex<Cache>,
}

#[cfg(feature = "client")]
#[derive(Default)]
struct Cache {
    token: Option<(String, i64)>,
    /// One app's token (its audience) → `(token, ms it stops being reused, expires_at seconds)`.
    by_audience: std::collections::HashMap<String, (String, i64, i64)>,
    /// The last timestamp signed, for every audience: one counter, so one device's token requests
    /// stay strictly increasing (and, the lock held across the call, serial).
    last_ts: i64,
}

#[cfg(feature = "client")]
impl Cache {
    /// Strictly increasing, even for two calls in one millisecond — the server refuses a repeat.
    fn next_ts(&mut self) -> i64 {
        let ts = now_ms().max(self.last_ts + 1);
        self.last_ts = ts;
        ts
    }
}

/// `POST /v1/token`'s answer, with `expires_at` (seconds) when the server gives it.
#[cfg(feature = "client")]
#[derive(Deserialize)]
struct Issued {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[cfg(feature = "client")]
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(feature = "client")]
impl Client {
    pub fn new(base: &str, product: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            .build()
            .into();
        Self { base: base.trim_end_matches('/').to_string(), product: product.to_string(), agent, cache: Mutex::default() }
    }

    fn post<T: serde::de::DeserializeOwned>(&self, path: &str, body: &serde_json::Value, bearer: Option<&str>) -> Result<T> {
        let mut req = self.agent.post(format!("{}{path}", self.base));
        if let Some(t) = bearer {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let mut res = req.send_json(body)?;
        Self::read(&mut res)
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str, bearer: &str) -> Result<T> {
        let mut res = self.agent.get(format!("{}{path}", self.base)).header("Authorization", format!("Bearer {bearer}")).call()?;
        Self::read(&mut res)
    }

    fn read<T: serde::de::DeserializeOwned>(res: &mut ureq::http::Response<ureq::Body>) -> Result<T> {
        let status = res.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Self::refused(status, res).into());
        }
        Ok(res.body_mut().read_json()?)
    }

    /// Why a call was refused. Only 401 is "signed out"; a 403 that names an app's audience is that
    /// app's alone.
    fn refused(status: u16, res: &mut ureq::http::Response<ureq::Body>) -> Refused {
        let mut error = || {
            let body = res.body_mut().read_to_string().unwrap_or_default();
            serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v["error"].as_str().map(str::to_string))
        };
        match status {
            401 => Refused::SignedOut,
            403 => match error().as_deref() {
                Some("audience_removed") => Refused::AudienceRemoved,
                Some("audience_not_allowed") => Refused::AudienceNotAllowed,
                _ => Refused::Status(403),
            },
            // A 400 is the clock unless it names the app (`unknown_audience`).
            400 => match error().as_deref() {
                Some("unknown_audience") => Refused::UnknownAudience,
                _ => Refused::Status(400),
            },
            s => Refused::Status(s),
        }
    }

    /// Ask to join an account. Show or open `url`, then [`Client::wait`].
    pub fn start(&self, id: &Identity, name: &str, os: &str) -> Result<Started> {
        self.post(
            "/v1/login/start",
            &serde_json::json!({ "product": self.product, "pubkey": id.public_hex(), "name": name, "os": os }),
            None,
        )
    }

    pub fn poll(&self, started: &Started) -> Result<Poll> {
        self.post("/v1/login/poll", &serde_json::json!({ "poll": started.poll }), None)
    }

    /// Block until the person approves (or the code expires), then remember the device id.
    pub fn wait(&self, started: &Started, id: &mut Identity) -> Result<i64> {
        let step = std::time::Duration::from_secs(started.interval.clamp(1, 10) as u64);
        loop {
            match self.poll(started)? {
                Poll::Done { device_id } => {
                    id.device_id = Some(device_id);
                    return Ok(device_id);
                }
                Poll::Expired => bail!("the sign-in link expired before it was approved"),
                Poll::Pending => std::thread::sleep(step),
            }
        }
    }

    /// Join with an enrollment token instead of a browser.
    pub fn enroll(&self, id: &mut Identity, token: &str, name: &str, os: &str) -> Result<i64> {
        #[derive(Deserialize)]
        struct Enrolled {
            device_id: i64,
        }
        let e: Enrolled = self.post(
            "/v1/login/enroll",
            &serde_json::json!({ "token": token, "product": self.product, "pubkey": id.public_hex(), "name": name, "os": os }),
            None,
        )?;
        id.device_id = Some(e.device_id);
        Ok(e.device_id)
    }

    /// A live access token, reused until a minute before it runs out.
    pub fn access_token(&self, id: &Identity) -> Result<String> {
        let Some(device_id) = id.device_id else { return Err(Refused::SignedOut.into()) };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((t, until)) = &cache.token
            && *until > now_ms() + 60_000
        {
            return Ok(t.clone());
        }
        let ts = cache.next_ts();
        let a: Access = self.post("/v1/token", &id.token_request(device_id, ts), None)?;
        cache.token = Some((a.access_token.clone(), now_ms() + a.expires_in * 1000));
        Ok(a.access_token)
    }

    /// A live access token **for one app** (`audience`) and when it expires (`expires_at`, seconds
    /// since the epoch), reused until a minute before it runs out — what a platform device (natdal)
    /// hands the app. Each audience has its own token; their requests share one timestamp counter
    /// and go one at a time. A refusal for that app alone is [`Refused::AudienceRemoved`] or
    /// [`Refused::AudienceNotAllowed`], never [`Refused::SignedOut`].
    pub fn access_token_for(&self, id: &Identity, audience: &str) -> Result<(String, i64)> {
        let Some(device_id) = id.device_id else { return Err(Refused::SignedOut.into()) };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((t, until, exp)) = cache.by_audience.get(audience)
            && *until > now_ms() + 60_000
        {
            return Ok((t.clone(), *exp));
        }
        let ts = cache.next_ts();
        let got = self.post::<Issued>("/v1/token", &id.token_request_for(device_id, ts, audience), None);
        let a = match got {
            Ok(a) => a,
            Err(e) => {
                cache.by_audience.remove(audience);
                return Err(e);
            }
        };
        let expires_at = a.expires_at.unwrap_or_else(|| now_ms() / 1000 + a.expires_in);
        cache.by_audience.insert(audience.to_string(), (a.access_token.clone(), now_ms() + a.expires_in * 1000, expires_at));
        Ok((a.access_token, expires_at))
    }

    /// Forget the cached token — after the plan changed, for instance.
    pub fn forget_token(&self) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).token = None;
    }

    /// Forget one app's cached token ([`Client::access_token_for`]).
    pub fn forget_token_for(&self, audience: &str) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).by_audience.remove(audience);
    }

    /// One app's peers (`audience`): the account's devices that app runs on, with the key it
    /// dials and is dialed by — old devices of that app and the app keys registered under
    /// platform devices alike. Same shape as [`Client::peers`].
    pub fn peers_for(&self, id: &Identity, audience: &str) -> Result<serde_json::Value> {
        let token = self.access_token_for(id, audience)?.0;
        self.for_audience(audience, self.peers_with(&token))
    }

    /// A call made with `audience`'s token: when it answers that the app was removed from this PC,
    /// the cached token is dropped too (the next one is refused the same until the web adds it back).
    fn for_audience<T>(&self, audience: &str, got: Result<T>) -> Result<T> {
        if let Err(e) = &got
            && matches!(e.downcast_ref::<Refused>(), Some(Refused::AudienceRemoved))
        {
            self.forget_token_for(audience);
        }
        got
    }

    /// [`Client::peers_for`] with a token the caller already has (an app given one by natdal).
    pub fn peers_with(&self, token: &str) -> Result<serde_json::Value> {
        self.get("/v1/peers", token)
    }

    /// Register an app's own key (`app` — its mesh identity, whose secret stays with the app) under
    /// this platform device for `audience`. Returns the app key's id. Registering the same key
    /// again is harmless; a new key for the same app replaces the old one.
    pub fn register_app_key(&self, id: &Identity, audience: &str, app: &Identity) -> Result<i64> {
        let Some(device_id) = id.device_id else { return Err(Refused::SignedOut.into()) };
        let token = self.access_token_for(id, audience)?.0;
        self.for_audience(audience, self.register_app_key_with(&token, device_id, audience, app))
    }

    /// [`Client::register_app_key`] with a token for `audience` the app was given (by natdal) for
    /// the platform device `device_id`.
    pub fn register_app_key_with(&self, token: &str, device_id: i64, audience: &str, app: &Identity) -> Result<i64> {
        #[derive(Deserialize)]
        struct Key {
            id: i64,
        }
        let k: Key = self.post("/v1/app-keys", &app.app_key_request(device_id, audience, now_ms()), Some(token))?;
        Ok(k.id)
    }

    /// **Hand an app's old device over to this platform device**: `old` is the app's own device
    /// from before (its key and id); afterwards that device is gone from the account and its key
    /// lives on as the app's key under this device — the same mesh identity. Same account only.
    /// The bearer is this device's token for `audience` (the old device's app, or natdal itself).
    /// Returns the platform device's id.
    pub fn handoff(&self, id: &Identity, audience: &str, old: &Identity) -> Result<i64> {
        let Some(device_id) = id.device_id else { return Err(Refused::SignedOut.into()) };
        let token = self.access_token_for(id, audience)?.0;
        self.for_audience(audience, self.handoff_with(&token, device_id, old))
    }

    /// [`Client::handoff`] with a token the app was given (by natdal) for the platform device
    /// `device_id`.
    pub fn handoff_with(&self, token: &str, device_id: i64, old: &Identity) -> Result<i64> {
        #[derive(Deserialize)]
        struct Done {
            device_id: i64,
        }
        let Some(old_id) = old.device_id else { bail!("the old device has no id") };
        let d: Done = self.post("/v1/devices/handoff", &old.handoff_request(old_id, device_id, now_ms()), Some(token))?;
        Ok(d.device_id)
    }

    pub fn me(&self, id: &Identity) -> Result<serde_json::Value> {
        self.get("/v1/me", &self.access_token(id)?)
    }

    pub fn devices(&self, id: &Identity) -> Result<serde_json::Value> {
        self.get("/v1/devices", &self.access_token(id)?)
    }

    /// This product's live devices on the account, with public keys — who this device may connect
    /// to and accept connections from.
    pub fn peers(&self, id: &Identity) -> Result<serde_json::Value> {
        self.get("/v1/peers", &self.access_token(id)?)
    }

    /// Make a token that lets other machines join without a browser.
    pub fn enroll_token(&self, id: &Identity, uses: i64, ttl_hours: i64) -> Result<String> {
        #[derive(Deserialize)]
        struct T {
            token: String,
        }
        let t: T = self.post("/v1/enroll-tokens", &serde_json::json!({ "uses": uses, "ttl_hours": ttl_hours }), Some(&self.access_token(id)?))?;
        Ok(t.token)
    }

    pub fn revoke(&self, id: &Identity, device_id: i64) -> Result<()> {
        let res = self
            .agent
            .delete(format!("{}/v1/devices/{device_id}", self.base))
            .header("Authorization", format!("Bearer {}", self.access_token(id)?))
            .call()?;
        let mut res = res;
        match res.status().as_u16() {
            204 => Ok(()),
            s => Err(Self::refused(s, &mut res).into()),
        }
    }
}

/// The claims inside an access token, read without checking the signature — for showing the plan
/// on screen. Anything that unlocks a feature on a server must verify with the JWKS instead.
pub fn peek(token: &str) -> Option<serde_json::Value> {
    let p = token.split('.').nth(1)?;
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn a_token_request_is_signed_by_this_device_for_this_moment() {
        let id = Identity::from_secret([7; 32], Some(3));
        let body = id.token_request(3, 1000);
        assert_eq!(body["device_id"], 3);
        assert_eq!(body["ts"], 1000);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body["sig"].as_str().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(id.public_hex()).unwrap().try_into().unwrap()).unwrap();
        assert!(vk.verify(token_message(3, 1000).as_bytes(), &sig).is_ok());
        assert!(vk.verify(token_message(3, 1001).as_bytes(), &sig).is_err(), "another moment");
    }

    fn verifies(id: &Identity, msg: &str, sig: &serde_json::Value) -> bool {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig.as_str().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(id.public_hex()).unwrap().try_into().unwrap()).unwrap();
        vk.verify(msg.as_bytes(), &sig).is_ok()
    }

    #[test]
    fn a_token_request_for_an_app_signs_the_audience_too() {
        let id = Identity::from_secret([7; 32], Some(3));
        let body = id.token_request_for(3, 1000, "guildlings");
        assert_eq!((body["device_id"].as_i64(), body["ts"].as_i64(), body["audience"].as_str()), (Some(3), Some(1000), Some("guildlings")));
        assert_eq!(token_message_for(3, 1000, "guildlings"), "natdal-token-v2\n3\n1000\nguildlings");
        assert!(verifies(&id, &token_message_for(3, 1000, "guildlings"), &body["sig"]));
        assert!(!verifies(&id, &token_message_for(3, 1000, "clipmesh"), &body["sig"]), "another app");
        assert!(!verifies(&id, &token_message(3, 1000), &body["sig"]), "not a v1 request");
    }

    #[test]
    fn an_app_key_and_a_handoff_are_signed_by_the_key_they_are_about() {
        let app = Identity::from_secret([8; 32], None);
        let body = app.app_key_request(11, "guildlings", 5);
        assert_eq!(body["pubkey"], app.public_hex());
        assert!(verifies(&app, "natdal-app-key-v1\n11\nguildlings\n5", &body["sig"]));
        let old = Identity::from_secret([9; 32], Some(8));
        let body = old.handoff_request(8, 11, 6);
        assert_eq!(body["old_device_id"], 8);
        assert!(verifies(&old, "natdal-handoff-v1\n8\n11\n6", &body["sig"]));
    }

    #[test]
    fn the_key_survives_a_round_trip_through_an_owner_only_file() {
        let dir = std::env::temp_dir().join(format!("natdal-device-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.json");
        let id = Identity::generate();
        let mut id2 = Identity::from_secret(id.secret(), Some(9));
        id2.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        id2 = Identity::load(&path).unwrap();
        assert_eq!(id2.public_hex(), id.public_hex());
        assert_eq!(id2.device_id, Some(9));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn peek_reads_the_claims() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"ent":["plus"]}"#);
        assert_eq!(peek(&format!("h.{payload}.s")).unwrap()["ent"][0], "plus");
        assert!(peek("not a token").is_none());
    }
}
