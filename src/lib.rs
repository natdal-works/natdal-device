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
}

/// The message a device signs to ask for an access token.
pub fn token_message(device_id: i64, ts: i64) -> String {
    format!("natdal-token-v1\n{device_id}\n{ts}")
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
pub enum Refused {
    /// The device was removed from the account, or its key is unknown: sign in again.
    #[error("this device is no longer signed in")]
    SignedOut,
    #[error("the server answered {0}")]
    Status(u16),
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
    last_ts: i64,
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
        if status == 401 {
            return Err(Refused::SignedOut.into());
        }
        if !(200..300).contains(&status) {
            return Err(Refused::Status(status).into());
        }
        Ok(res.body_mut().read_json()?)
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
        // Strictly increasing, even for two calls in one millisecond — the server refuses a repeat.
        let ts = now_ms().max(cache.last_ts + 1);
        cache.last_ts = ts;
        let a: Access = self.post("/v1/token", &id.token_request(device_id, ts), None)?;
        cache.token = Some((a.access_token.clone(), now_ms() + a.expires_in * 1000));
        Ok(a.access_token)
    }

    /// Forget the cached token — after the plan changed, for instance.
    pub fn forget_token(&self) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).token = None;
    }

    pub fn me(&self, id: &Identity) -> Result<serde_json::Value> {
        self.get("/v1/me", &self.access_token(id)?)
    }

    pub fn devices(&self, id: &Identity) -> Result<serde_json::Value> {
        self.get("/v1/devices", &self.access_token(id)?)
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
        match res.status().as_u16() {
            204 => Ok(()),
            401 => Err(Refused::SignedOut.into()),
            s => Err(Refused::Status(s).into()),
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
