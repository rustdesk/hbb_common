//! Sealed datagrams between a client and its rendezvous server, one message per datagram and no
//! handshake to lose or reorder.
//!
//! A client with no session sends a hello: an HPKE (RFC 9180) base-mode single shot to the
//! server's X25519 key, which is its signing key converted, so a client that trusts the server
//! key trusts this one. A hello carries a signature by the device key the server keeps on record
//! for the ID, which is how the server tells the device from anyone else sending under its ID.
//! The server answers with a welcome sealed under a key exported from that HPKE context and a
//! fresh nonce, the way Oblivious HTTP (RFC 9458) answers a request, and the welcome hands the
//! client a session key. The server derives that key from a process secret and the key id, the
//! way PSP derives receive keys from the SPI, so it stores no key per client. Every later
//! datagram in either direction is data: the key id, a packet number and an AEAD under the
//! session key's subkey for that direction.
//!
//! Every datagram starts with `MAGIC`, whose zero byte is a protobuf field number no message
//! can have, so a build without this module fails to parse one and drops it.

use sodiumoxide::{
    crypto::{
        aead::chacha20poly1305_ietf as aead, auth::hmacsha256, generichash,
        scalarmult::curve25519 as x25519, sign,
    },
    randombytes::randombytes_into,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: [u8; 3] = [0x00, b'R', b'Z'];
/// A capability level, not a format id: a sender never uses a higher one than its peer has
/// shown, and a receiver drops any version it does not know.
pub const VERSION: u8 = 1;
/// Server capability: every UDP push to this client is sealed, so a plaintext one is forged.
pub const CAP_PUSHES_SEALED: u8 = 1;

const KIND_HELLO: u8 = 1;
const KIND_WELCOME: u8 = 2;
const KIND_TO_SERVER: u8 = 3;
const KIND_TO_CLIENT: u8 = 4;

// How a hello says who sent it. A later version may add kinds, a post-quantum signature among
// them; this one drops a hello with a kind it does not know.
const AUTH_NONE: u8 = 0;
const AUTH_DEVICE: u8 = 1;

const HDR: usize = 5;
const ENC: usize = 32;
const ID: usize = 8;
const PN: usize = 8;
const KEY: usize = 32;
const NONCE: usize = 32;
const TS: usize = 8;
const SIG: usize = 64;
/// The shortest hello: unsigned, with no payload.
const MIN_HELLO: usize = HDR + ENC + 1 + aead::TAGBYTES;

const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";
const HELLO_INFO: &[u8] = b"rustdesk udp seal\x00";
const WELCOME_EXPORT: &[u8] = b"rustdesk udp seal welcome";
const DEVICE_LABEL: &[u8] = b"rustdesk udp seal device";
const SESSION_LABEL: &[u8] = b"rustdesk udp seal session";
const DIRECTION_LABEL: &[u8] = b"rustdesk udp seal direction";

/// Whether a datagram is one of ours. One that is but does not open is dropped, never read as
/// plaintext.
pub fn is_sealed(datagram: &[u8]) -> bool {
    datagram.starts_with(&MAGIC)
}

/// Whether a datagram is a hello, the one kind that costs the server an X25519.
pub fn is_hello(datagram: &[u8]) -> bool {
    kind(datagram) == Some(KIND_HELLO) && datagram.len() >= MIN_HELLO
}

fn kind(datagram: &[u8]) -> Option<u8> {
    if datagram.len() < HDR || datagram[..3] != MAGIC || datagram[3] != VERSION {
        return None;
    }
    match datagram[4] {
        k @ KIND_HELLO..=KIND_TO_CLIENT => Some(k),
        _ => None,
    }
}

fn header(kind: u8) -> [u8; HDR] {
    [MAGIC[0], MAGIC[1], MAGIC[2], VERSION, kind]
}

fn array<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != N {
        return None;
    }
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Some(a)
}

fn key_id_of(datagram: &[u8]) -> Option<u64> {
    array(datagram.get(HDR..HDR + ID)?).map(u64::from_be_bytes)
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = hmacsha256::State::init(key);
    for part in parts {
        state.update(part);
    }
    state.finalize().0
}

fn labeled_extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac(salt, &[b"HPKE-v1", suite, label, ikm])
}

// One HKDF-Expand block: nothing here asks for more than a SHA-256 output. The caller cuts the
// block to `len`, which only goes into the info as RFC 9180 says.
fn labeled_expand(prk: &[u8; 32], suite: &[u8], label: &[u8], info: &[u8], len: u16) -> [u8; 32] {
    hmac(
        prk,
        &[&len.to_be_bytes(), b"HPKE-v1", suite, label, info, &[1]],
    )
}

fn blake(key: &[u8], parts: &[&[u8]]) -> Option<[u8; 32]> {
    let mut state = generichash::State::new(Some(32), Some(key)).ok()?;
    for part in parts {
        state.update(part).ok()?;
    }
    array(state.finalize().ok()?.as_ref())
}

fn seal_aead(key: &[u8; 32], nonce: [u8; 12], ad: &[u8], plain: &[u8]) -> Vec<u8> {
    aead::seal(plain, Some(ad), &aead::Nonce(nonce), &aead::Key(*key))
}

fn open_aead(key: &[u8; 32], nonce: [u8; 12], ad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    aead::open(sealed, Some(ad), &aead::Nonce(nonce), &aead::Key(*key)).ok()
}

fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Option<[u8; 32]> {
    // Fails on the all-zero output, the check RFC 9180 requires of X25519.
    x25519::scalarmult(&x25519::Scalar(*sk), &x25519::GroupElement(*pk))
        .ok()
        .map(|g| g.0)
}

/// An HPKE context after the key schedule, single shot: sequence number 0 only.
struct Hpke {
    key: [u8; 32],
    nonce: [u8; 12],
    exporter: [u8; 32],
}

impl Hpke {
    fn new(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32], info: &[u8]) -> Self {
        let eae_prk = labeled_extract(&[], KEM_SUITE, b"eae_prk", dh);
        let shared = labeled_expand(
            &eae_prk,
            KEM_SUITE,
            b"shared_secret",
            &[&enc[..], pk_r].concat(),
            32,
        );
        Self::schedule(&shared, info)
    }

    fn schedule(shared: &[u8; 32], info: &[u8]) -> Self {
        let mut context = [0u8; 65];
        context[1..33].copy_from_slice(&labeled_extract(&[], HPKE_SUITE, b"psk_id_hash", &[]));
        context[33..].copy_from_slice(&labeled_extract(&[], HPKE_SUITE, b"info_hash", info));
        let secret = labeled_extract(shared, HPKE_SUITE, b"secret", &[]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(
            &labeled_expand(&secret, HPKE_SUITE, b"base_nonce", &context, 12)[..12],
        );
        Self {
            key: labeled_expand(&secret, HPKE_SUITE, b"key", &context, 32),
            nonce,
            exporter: labeled_expand(&secret, HPKE_SUITE, b"exp", &context, 32),
        }
    }

    fn export(&self, context: &[u8]) -> [u8; 32] {
        labeled_expand(&self.exporter, HPKE_SUITE, b"sec", context, 32)
    }
}

fn hello_info() -> Vec<u8> {
    [HELLO_INFO, &header(KIND_HELLO)].concat()
}

fn device_message(server: &[u8; 32], enc: &[u8; 32], ts: u64) -> Vec<u8> {
    [DEVICE_LABEL, server, enc, &ts.to_be_bytes()].concat()
}

// RFC 9458 4.4: the response key comes from the request's exported secret, its `enc` and a
// response nonce. The nonce is random per welcome rather than the key id, which a restart
// hands out again: two welcomes for one replayed hello must not share a keystream.
fn welcome_keys(secret: &[u8; 32], enc: &[u8; 32], nonce: &[u8]) -> ([u8; 32], [u8; 12]) {
    let prk = hmac(&[&enc[..], nonce].concat(), &[secret]);
    let mut aead_nonce = [0u8; 12];
    aead_nonce.copy_from_slice(&hmac(&prk, &[b"nonce", &[1]])[..12]);
    (hmac(&prk, &[b"key", &[1]]), aead_nonce)
}

fn session_key(master: &[u8; 32], key_id: u64) -> Option<[u8; 32]> {
    blake(master, &[SESSION_LABEL, &key_id.to_be_bytes()])
}

fn pn_nonce(pn: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&pn.to_be_bytes());
    nonce
}

fn seal_data(
    session: &[u8; 32],
    kind: u8,
    key_id: u64,
    pn: u64,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let key = blake(session, &[DIRECTION_LABEL, &[kind]])?;
    let mut out = header(kind).to_vec();
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(&pn.to_be_bytes());
    let sealed = seal_aead(&key, pn_nonce(pn), &out, payload);
    out.extend_from_slice(&sealed);
    Some(out)
}

fn open_data(session: &[u8; 32], kind: u8, datagram: &[u8]) -> Option<(u64, Vec<u8>)> {
    let ad = datagram.get(..HDR + ID + PN)?;
    let pn = u64::from_be_bytes(array(&ad[HDR + ID..])?);
    let key = blake(session, &[DIRECTION_LABEL, &[kind]])?;
    open_aead(&key, pn_nonce(pn), ad, &datagram[HDR + ID + PN..]).map(|payload| (pn, payload))
}

const WINDOW: u64 = 1024;

/// The packet numbers a receiver has accepted under one key: the highest and the 1023 below it,
/// one bit each in a ring indexed by the number.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplayWindow {
    top: u64,
    bits: [u64; WINDOW as usize / 64],
}

impl ReplayWindow {
    /// Whether `pn` is new, recording it if so.
    pub fn accept(&mut self, pn: u64) -> bool {
        let n = match pn.checked_add(1) {
            Some(n) => n,
            None => return false,
        };
        if n > self.top {
            if n - self.top >= WINDOW {
                self.bits = Default::default();
            } else {
                for m in self.top + 1..n {
                    self.set(m, false);
                }
            }
            self.top = n;
        } else if self.top - n >= WINDOW || self.get(n) {
            return false;
        }
        self.set(n, true);
        true
    }

    fn get(&self, n: u64) -> bool {
        self.bits[(n % WINDOW / 64) as usize] >> (n % 64) & 1 == 1
    }

    fn set(&mut self, n: u64, seen: bool) {
        let word = &mut self.bits[(n % WINDOW / 64) as usize];
        if seen {
            *word |= 1 << (n % 64);
        } else {
            *word &= !(1 << (n % 64));
        }
    }
}

#[derive(Debug)]
struct DeviceAuth {
    ts: u64,
    sig: [u8; SIG],
    message: Vec<u8>,
}

/// What the server opened.
#[derive(Debug)]
pub struct Opened {
    pub key_id: u64,
    /// `None` for a hello, which carries no packet number.
    pub pn: Option<u64>,
    pub payload: Vec<u8>,
    auth: Option<DeviceAuth>,
}

impl Opened {
    /// The time a hello was signed at, if `device`, the key on record for the ID it registers,
    /// signed it.
    pub fn signed_by(&self, device: &[u8]) -> Option<u64> {
        let auth = self.auth.as_ref()?;
        let device = sign::PublicKey::from_slice(device)?;
        let sig = sign::Signature::from_bytes(&auth.sig).ok()?;
        sign::verify_detached(&sig, &auth.message, &device).then_some(auth.ts)
    }
}

struct WelcomeSecret {
    secret: [u8; 32],
    enc: [u8; 32],
}

/// How the server seals what it sends back: the welcome for the hello it answers, data after.
pub struct Reply {
    key_id: u64,
    welcome: Option<WelcomeSecret>,
}

impl Reply {
    /// For a push to a client whose session has `key_id`.
    pub fn push(key_id: u64) -> Self {
        Self {
            key_id,
            welcome: None,
        }
    }
}

pub struct ServerKey {
    sk: [u8; 32],
    pk: [u8; 32],
    master: [u8; 32],
}

impl ServerKey {
    /// `master` derives every session key: random per process, so a restart retires them all.
    pub fn new(sign_sk: &sign::SecretKey, master: [u8; 32]) -> Option<Self> {
        let sign_pk = sign::PublicKey::from_slice(&sign_sk.0[32..])?;
        Some(Self {
            sk: sign::ed25519::to_curve25519_sk(sign_sk).ok()?.0,
            pk: sign::ed25519::to_curve25519_pk(&sign_pk).ok()?.0,
            master,
        })
    }

    /// Opens a hello or a data datagram. `new_key_id` is called once per hello that opens and
    /// must never repeat a value for the same `master`.
    pub fn open(
        &self,
        datagram: &[u8],
        new_key_id: impl FnOnce() -> u64,
    ) -> Option<(Opened, Reply)> {
        match kind(datagram)? {
            KIND_HELLO if is_hello(datagram) => {
                let enc = array(datagram.get(HDR..HDR + ENC)?)?;
                let hpke = Hpke::new(&dh(&self.sk, &enc)?, &enc, &self.pk, &hello_info());
                let plain = open_aead(&hpke.key, hpke.nonce, &[], &datagram[HDR + ENC..])?;
                let (auth, payload) = match plain.split_first()? {
                    (&AUTH_NONE, rest) => (None, rest),
                    (&AUTH_DEVICE, rest) if rest.len() >= TS + SIG => {
                        let ts = u64::from_be_bytes(array(&rest[..TS])?);
                        let auth = DeviceAuth {
                            ts,
                            sig: array(&rest[TS..TS + SIG])?,
                            message: device_message(&self.pk, &enc, ts),
                        };
                        (Some(auth), &rest[TS + SIG..])
                    }
                    _ => return None,
                };
                let key_id = new_key_id();
                let welcome = WelcomeSecret {
                    secret: hpke.export(WELCOME_EXPORT),
                    enc,
                };
                Some((
                    Opened {
                        key_id,
                        pn: None,
                        payload: payload.to_vec(),
                        auth,
                    },
                    Reply {
                        key_id,
                        welcome: Some(welcome),
                    },
                ))
            }
            KIND_TO_SERVER => {
                let key_id = key_id_of(datagram)?;
                let (pn, payload) = open_data(
                    &session_key(&self.master, key_id)?,
                    KIND_TO_SERVER,
                    datagram,
                )?;
                let opened = Opened {
                    key_id,
                    pn: Some(pn),
                    payload,
                    auth: None,
                };
                Some((opened, Reply::push(key_id)))
            }
            _ => None,
        }
    }

    /// Seals one datagram to the client: the welcome first if `reply` still holds it. `pn` is
    /// called for data only and must never repeat a value for the same `master`.
    pub fn seal(
        &self,
        reply: &mut Reply,
        caps: u8,
        payload: &[u8],
        pn: impl FnOnce() -> u64,
    ) -> Option<Vec<u8>> {
        let session = session_key(&self.master, reply.key_id)?;
        match reply.welcome.take() {
            Some(welcome) => {
                let mut nonce = [0u8; NONCE];
                randombytes_into(&mut nonce);
                let mut out = header(KIND_WELCOME).to_vec();
                out.extend_from_slice(&reply.key_id.to_be_bytes());
                out.extend_from_slice(&nonce);
                let (key, aead_nonce) = welcome_keys(&welcome.secret, &welcome.enc, &nonce);
                let plain = [&[caps][..], &session, payload].concat();
                let sealed = seal_aead(&key, aead_nonce, &out, &plain);
                out.extend_from_slice(&sealed);
                Some(out)
            }
            None => seal_data(&session, KIND_TO_CLIENT, reply.key_id, pn(), payload),
        }
    }
}

struct Hello {
    enc: [u8; 32],
    hpke: Hpke,
    signed: bool,
}

struct Session {
    key_id: u64,
    key: [u8; 32],
    caps: u8,
    next_pn: u64,
    window: ReplayWindow,
    signed: bool,
}

/// One client socket's side: the hello in flight, then the session it got.
pub struct ClientSeal {
    pk: [u8; 32],
    device: Option<sign::SecretKey>,
    last_ts: u64,
    hello: Option<Hello>,
    session: Option<Session>,
}

impl ClientSeal {
    /// `device` signs hellos, so the server can tell this device from others using its ID.
    pub fn new(server: &sign::PublicKey, device: Option<sign::SecretKey>) -> Option<Self> {
        Some(Self {
            pk: sign::ed25519::to_curve25519_pk(server).ok()?.0,
            device,
            last_ts: 0,
            hello: None,
            session: None,
        })
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    pub fn pushes_sealed(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.caps & CAP_PUSHES_SEALED != 0)
    }

    /// Whether the session came from a hello the server could not tie to this device, an empty
    /// one, which a signed hello should replace.
    pub fn needs_signed_hello(&self) -> bool {
        self.device.is_some() && self.session.as_ref().is_some_and(|s| !s.signed)
    }

    /// The next RegisterPeer goes as a signed hello even though this session came from one: the
    /// server may not have had the device's key to check it against then.
    pub fn require_signed_hello(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.signed = false;
        }
    }

    /// Whether hellos are signed by the device key whose public half is `pk`.
    pub fn signs_as(&self, pk: &[u8]) -> bool {
        self.device.as_ref().is_some_and(|sk| sk.0[32..] == *pk)
    }

    /// The device key changed: later hellos are signed by `device`. The session stays.
    pub fn set_device(&mut self, device: Option<sign::SecretKey>) {
        self.device = device;
    }

    /// Forgets the session, so the next datagram is a hello.
    pub fn reset(&mut self) {
        self.hello = None;
        self.session = None;
    }

    /// Data under the session, or else a fresh hello, which replaces any hello still unanswered.
    pub fn seal(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if let Some(s) = self.session.as_mut() {
            let pn = s.next_pn;
            s.next_pn += 1;
            return seal_data(&s.key, KIND_TO_SERVER, s.key_id, pn, payload);
        }
        self.hello(payload)
    }

    /// A fresh hello even under a session, which stays in use until the welcome replaces it.
    pub fn hello(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        // Strictly rising: the server takes a signed hello over a live seal only when newer.
        let ts = now.max(self.last_ts + 1);
        self.last_ts = ts;
        let mut sk = [0u8; 32];
        randombytes_into(&mut sk);
        self.hello_with(sk, payload, ts)
    }

    fn hello_with(&mut self, sk: [u8; 32], payload: &[u8], ts: u64) -> Option<Vec<u8>> {
        let enc = x25519::scalarmult_base(&x25519::Scalar(sk)).0;
        let hpke = Hpke::new(&dh(&sk, &self.pk)?, &enc, &self.pk, &hello_info());
        let mut plain = Vec::with_capacity(1 + TS + SIG + payload.len());
        match &self.device {
            Some(device) => {
                plain.push(AUTH_DEVICE);
                plain.extend_from_slice(&ts.to_be_bytes());
                let message = device_message(&self.pk, &enc, ts);
                plain.extend_from_slice(sign::sign_detached(&message, device).as_ref());
            }
            None => plain.push(AUTH_NONE),
        }
        plain.extend_from_slice(payload);
        let mut out = header(KIND_HELLO).to_vec();
        out.extend_from_slice(&enc);
        out.extend_from_slice(&seal_aead(&hpke.key, hpke.nonce, &[], &plain));
        self.hello = Some(Hello {
            enc,
            hpke,
            signed: self.device.is_some() && !payload.is_empty(),
        });
        Some(out)
    }

    /// Opens the welcome to the latest hello, which starts the session, or data under it.
    pub fn open(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        match kind(datagram)? {
            KIND_WELCOME => {
                let hello = self.hello.as_ref()?;
                let ad = datagram.get(..HDR + ID + NONCE)?;
                let (key, nonce) = welcome_keys(
                    &hello.hpke.export(WELCOME_EXPORT),
                    &hello.enc,
                    &ad[HDR + ID..],
                );
                let plain = open_aead(&key, nonce, ad, &datagram[HDR + ID + NONCE..])?;
                if plain.len() < 1 + KEY {
                    return None;
                }
                self.session = Some(Session {
                    key_id: key_id_of(datagram)?,
                    key: array(&plain[1..1 + KEY])?,
                    caps: plain[0],
                    next_pn: 0,
                    window: ReplayWindow::default(),
                    signed: hello.signed,
                });
                self.hello = None;
                Some(plain[1 + KEY..].to_vec())
            }
            KIND_TO_CLIENT => {
                let s = self.session.as_mut()?;
                if key_id_of(datagram)? != s.key_id {
                    return None;
                }
                let (pn, payload) = open_data(&s.key, KIND_TO_CLIENT, datagram)?;
                if s.window.accept(pn) {
                    Some(payload)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        array(&hex(s)).unwrap()
    }

    fn pair() -> (ClientSeal, ServerKey) {
        let (pk, sk) = sign::gen_keypair();
        let device = sign::gen_keypair().1;
        (
            ClientSeal::new(&pk, Some(device)).unwrap(),
            ServerKey::new(&sk, [7u8; 32]).unwrap(),
        )
    }

    // Hello, then welcome; returns the key id the session got.
    fn established() -> (ClientSeal, ServerKey, u64) {
        let (mut client, server) = pair();
        let hello = client.seal(b"register").unwrap();
        let (opened, mut reply) = server.open(&hello, || 42).unwrap();
        assert_eq!(
            (opened.key_id, opened.pn, &opened.payload[..]),
            (42, None, &b"register"[..])
        );
        let welcome = server
            .seal(
                &mut reply,
                CAP_PUSHES_SEALED,
                b"registered",
                || unreachable!(),
            )
            .unwrap();
        assert_eq!(client.open(&welcome).unwrap(), b"registered");
        assert!(client.has_session() && client.pushes_sealed());
        (client, server, 42)
    }

    // RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode.
    #[test]
    fn hpke_matches_rfc_9180_test_vectors() {
        let sk_e = hex32("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let pk_e = hex32("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let sk_r = hex32("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_r = hex32("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        assert_eq!(x25519::scalarmult_base(&x25519::Scalar(sk_e)).0, pk_e);
        let sender = Hpke::new(&dh(&sk_e, &pk_r).unwrap(), &pk_e, &pk_r, &info);
        let receiver = Hpke::new(&dh(&sk_r, &pk_e).unwrap(), &pk_e, &pk_r, &info);
        for h in [&sender, &receiver] {
            assert_eq!(
                h.key,
                hex32("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
            );
            assert_eq!(h.nonce[..], hex("5c4d98150661b848853b547f")[..]);
            assert_eq!(
                h.exporter,
                hex32("a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922")
            );
        }
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let ct = seal_aead(&sender.key, sender.nonce, &hex("436f756e742d30"), &pt);
        assert_eq!(
            ct,
            hex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db 21993c62ce81883d2dd1b51a28")
        );
        assert_eq!(
            sender.export(&[]),
            hex32("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e")
        );
        assert_eq!(
            sender.export(&[0]),
            hex32("8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69")
        );
        assert_eq!(
            sender.export(b"TestContext"),
            hex32("5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53")
        );
    }

    #[test]
    fn a_session_carries_data_both_ways_and_refuses_replays() {
        let (mut client, server, key_id) = established();
        for i in 0..3u64 {
            let up = client.seal(b"heartbeat").unwrap();
            let (opened, _) = server.open(&up, || unreachable!()).unwrap();
            assert_eq!(
                (opened.key_id, opened.pn, &opened.payload[..]),
                (key_id, Some(i), &b"heartbeat"[..])
            );
        }
        let mut push = Reply::push(key_id);
        let down = server.seal(&mut push, 0, b"punch hole", || 9).unwrap();
        assert_eq!(client.open(&down).unwrap(), b"punch hole");
        assert!(client.open(&down).is_none(), "a replayed push is refused");
        let older = server.seal(&mut push, 0, b"late", || 3).unwrap();
        assert_eq!(
            client.open(&older).unwrap(),
            b"late",
            "a reordered push within the window is kept"
        );
    }

    #[test]
    fn every_changed_byte_is_refused() {
        let (mut client, server) = pair();
        let hello = client.seal(b"register").unwrap();
        let (_, mut reply) = server.open(&hello, || 1).unwrap();
        let welcome = server
            .seal(&mut reply, 0, b"ok", || unreachable!())
            .unwrap();
        for i in 0..hello.len() {
            let mut bad = hello.clone();
            bad[i] ^= 0x01;
            assert!(server.open(&bad, || 2).is_none(), "hello byte {}", i);
        }
        for i in 0..welcome.len() {
            let mut bad = welcome.clone();
            bad[i] ^= 0x01;
            assert!(client.open(&bad).is_none(), "welcome byte {}", i);
        }
        client.open(&welcome).unwrap();
        let up = client.seal(b"heartbeat").unwrap();
        for i in 0..up.len() {
            let mut bad = up.clone();
            bad[i] ^= 0x01;
            assert!(server.open(&bad, || 3).is_none(), "data byte {}", i);
        }
    }

    #[test]
    fn unknown_versions_kinds_and_short_input_are_dropped() {
        let (mut client, server, key_id) = established();
        let up = client.seal(b"heartbeat").unwrap();
        let mut down = server
            .seal(&mut Reply::push(key_id), 0, b"x", || 0)
            .unwrap();
        for (i, v) in [(3, 2u8), (4, 0), (4, 5), (4, 0x83)] {
            let mut bad = up.clone();
            bad[i] = v;
            assert!(server.open(&bad, || 9).is_none());
            let saved = down[i];
            down[i] = v;
            assert!(client.open(&down).is_none());
            down[i] = saved;
        }
        for n in 0..up.len() {
            assert!(server.open(&up[..n], || 9).is_none());
        }
        for n in 0..down.len() {
            assert!(client.open(&down[..n]).is_none());
        }
    }

    #[test]
    fn a_datagram_does_not_open_in_the_other_direction_or_for_another_server() {
        let (mut client, server, key_id) = established();
        let up = client.seal(b"heartbeat").unwrap();
        assert!(client.open(&up).is_none());
        let down = server
            .seal(&mut Reply::push(key_id), 0, b"x", || 0)
            .unwrap();
        assert!(server.open(&down, || 9).is_none());
        let other = ServerKey::new(&sign::gen_keypair().1, [8u8; 32]).unwrap();
        let hello = ClientSeal::new(&sign::gen_keypair().0, None)
            .unwrap()
            .seal(b"r")
            .unwrap();
        assert!(other.open(&up, || 9).is_none());
        assert!(server.open(&hello, || 9).is_none());
    }

    #[test]
    fn an_old_build_cannot_parse_any_sealed_datagram() {
        use protobuf::Message as _;
        let (mut client, server) = pair();
        let hello = client.seal(b"\x0a\x03abc").unwrap();
        let (_, mut reply) = server.open(&hello, || 1).unwrap();
        let welcome = server.seal(&mut reply, 0, b"", || unreachable!()).unwrap();
        client.open(&welcome).unwrap();
        let up = client.seal(b"").unwrap();
        let down = server.seal(&mut Reply::push(1), 0, b"", || 0).unwrap();
        for d in [hello, welcome, up, down] {
            assert!(crate::rendezvous_proto::RendezvousMessage::parse_from_bytes(&d).is_err());
        }
    }

    #[test]
    fn a_datagram_shorter_than_any_hello_is_not_taken_for_one() {
        let (pk, sk) = sign::gen_keypair();
        let server = ServerKey::new(&sk, [7u8; 32]).unwrap();
        let shortest = ClientSeal::new(&pk, None).unwrap().seal(b"").unwrap();
        assert!(is_hello(&shortest) && server.open(&shortest, || 1).is_some());
        let short = &shortest[..shortest.len() - 1];
        assert!(
            !is_hello(short),
            "the server would charge its hello budget for it"
        );
        assert!(server.open(short, || unreachable!()).is_none());
    }

    #[test]
    fn an_empty_hello_still_gets_a_session_but_asks_for_a_signed_one() {
        let (mut client, server) = pair();
        let hello = client.seal(b"").unwrap();
        let (opened, mut reply) = server.open(&hello, || 5).unwrap();
        assert!(opened.payload.is_empty());
        let welcome = server.seal(&mut reply, 0, b"", || unreachable!()).unwrap();
        assert!(client.open(&welcome).unwrap().is_empty());
        assert!(client.has_session() && client.needs_signed_hello());
        let (mut client, _, _) = established();
        assert!(!client.needs_signed_hello());
        client.require_signed_hello();
        assert!(client.needs_signed_hello());
    }

    #[test]
    fn only_the_latest_hello_is_welcomed_and_only_once() {
        let (mut client, server) = pair();
        let first = client.seal(b"a").unwrap();
        let second = client.seal(b"b").unwrap();
        let (_, mut late) = server.open(&first, || 1).unwrap();
        let (_, mut current) = server.open(&second, || 2).unwrap();
        let late = server.seal(&mut late, 0, b"", || unreachable!()).unwrap();
        let current = server
            .seal(&mut current, 0, b"", || unreachable!())
            .unwrap();
        assert!(client.open(&late).is_none());
        assert!(client.open(&current).is_some());
        assert!(
            client.open(&current).is_none(),
            "a duplicate welcome does not restart the session"
        );
    }

    #[test]
    fn the_replay_window_keeps_1024_numbers() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(0) && !w.accept(0));
        assert!(w.accept(2000) && w.accept(977) && !w.accept(977) && !w.accept(976));
        assert!(w.accept(1999) && !w.accept(2000) && !w.accept(u64::MAX));
        assert!(
            w.accept(3000) && w.accept(2001) && !w.accept(2001),
            "a number the window moved past does not shadow one 1024 above it"
        );
    }

    // A restart starts the key ids over, so a hello replayed into the same slot gets the same
    // key id under a new master: its welcome must still use a new keystream.
    #[test]
    fn a_replayed_hello_after_a_restart_gets_a_new_keystream() {
        let (pk, sk) = sign::gen_keypair();
        let hello = ClientSeal::new(&pk, None).unwrap().seal(b"r").unwrap();
        let welcome = |master: [u8; 32]| {
            let server = ServerKey::new(&sk, master).unwrap();
            let (_, mut reply) = server.open(&hello, || 1).unwrap();
            server.seal(&mut reply, 0, b"", || unreachable!()).unwrap()
        };
        let (a, b) = (welcome([1u8; 32]), welcome([2u8; 32]));
        let keys: Vec<u8> = session_key(&[1u8; 32], 1)
            .unwrap()
            .iter()
            .zip(&session_key(&[2u8; 32], 1).unwrap())
            .map(|(x, y)| x ^ y)
            .collect();
        let start = HDR + ID + NONCE + 1;
        let sealed: Vec<u8> = a[start..start + KEY]
            .iter()
            .zip(&b[start..start + KEY])
            .map(|(x, y)| x ^ y)
            .collect();
        assert_ne!(sealed, keys);
    }

    #[test]
    fn a_new_device_key_signs_the_hellos_after_it() {
        let (pk, sk) = sign::gen_keypair();
        let server = ServerKey::new(&sk, [7u8; 32]).unwrap();
        let (old_pk, old_sk) = sign::gen_keypair();
        let (new_pk, new_sk) = sign::gen_keypair();
        let mut client = ClientSeal::new(&pk, Some(old_sk)).unwrap();
        assert!(client.signs_as(old_pk.as_ref()) && !client.signs_as(new_pk.as_ref()));
        client.set_device(Some(new_sk));
        let (opened, _) = server.open(&client.seal(b"r").unwrap(), || 1).unwrap();
        assert!(opened.signed_by(new_pk.as_ref()).is_some());
        assert!(opened.signed_by(old_pk.as_ref()).is_none());
    }

    #[test]
    fn a_hello_names_the_device_that_signed_it_and_a_rising_time() {
        let (pk, sk) = sign::gen_keypair();
        let (device_pk, device_sk) = sign::gen_keypair();
        let server = ServerKey::new(&sk, [7u8; 32]).unwrap();
        let mut client = ClientSeal::new(&pk, Some(device_sk)).unwrap();
        let (first, _) = server.open(&client.seal(b"r").unwrap(), || 1).unwrap();
        let (second, _) = server.open(&client.seal(b"r").unwrap(), || 2).unwrap();
        let first_ts = first.signed_by(device_pk.as_ref()).unwrap();
        assert!(second.signed_by(device_pk.as_ref()).unwrap() > first_ts);
        assert!(first.signed_by(sign::gen_keypair().0.as_ref()).is_none());
        let unsigned = ClientSeal::new(&pk, None).unwrap().seal(b"r").unwrap();
        let (unsigned, _) = server.open(&unsigned, || 3).unwrap();
        assert!(unsigned.signed_by(device_pk.as_ref()).is_none());
    }
}
