//! WebRTC transport for RustDesk streams.
//!
//! # webrtc crate upgrade checklist
//!
//! The webrtc crate version is MSRV-pinned in Cargo.toml (see the comment there). Beyond plain
//! API compatibility, this module relies on webrtc-rs *internals* that its public API does not
//! guarantee. All of them were verified against webrtc 0.13 (webrtc-data 0.11, webrtc-sctp 0.12);
//! re-verify each against the new crate sources when bumping:
//!
//! - **Send backpressure is bounded**: `data::DataChannel::write` PARKS when webrtc-sctp's
//!   PendingQueue is full (byte-counting semaphore, `QUEUE_BYTES_LIMIT` = 128 KiB; permits return
//!   as chunks drain) and inflight data is cwnd/rwnd-capped (peer default rwnd 1 MiB).
//!   `send_bytes` depends on this both for bounded memory on slow links and for its
//!   send_timeout-then-close semantics. If a new version buffers unboundedly instead, video can
//!   OOM a slow session and the send timeout never fires.
//! - **Max SCTP message size 65536**: `MAX_FRAGMENT_PAYLOAD` + 1 header byte must stay below it.
//! - **The successful read path is cancel-safe**: `read_sctp` dequeues synchronously and returns
//!   with no `.await` after it, and `read_data_channel` adds none on the user-data path. So
//!   `next_timeout`, which drops that future routinely, cannot lose a fragment — a version that
//!   awaited after dequeuing would, undetectably, since the header carries no length or checksum.
//!   Scope: the *read*. `read_data_channel` does await after dequeuing on its ErrShortBuffer and
//!   DCEP branches, and `next()` itself awaits `pc.close()` on its error paths — and
//!   `RTCPeerConnection::close` latches `is_closed` before its first await, so a cancelled close
//!   silently makes every later close a no-op and leaves the pc in `SESSIONS`.
//! - **`detach()` is an idempotent Arc clone with no close-on-drop** (`detached_dc` caches it and
//!   clones are shared across `WebRTCStream` clones).
//! - **`on_*` handlers are stored inside the pc**: a handler capturing a strong
//!   `Arc<RTCPeerConnection>` forms an uncollectable cycle and leaks the pc permanently — see the
//!   `Arc::downgrade` in `new()`; any newly added handler must follow it.
//! - **`Disconnected` peer-connection state is transient/recoverable** (ICE consent lapse);
//!   only `Failed`/`Closed` are treated as terminal by the state handler.
//! - **`RTCIceCandidatePair`'s `Display` format**: its candidates are private in 0.13, so
//!   `is_relayed()` reads the candidate type out of
//!   `"(local) {protocol} {typ} {addr}:{port}{related} <-> (remote) ..."` by position. 0.17+
//!   makes the fields `pub`; switch to them and delete the parse. (It cannot use the stats
//!   report's `nominated` flag instead: webrtc-ice sets that per checklist entry and never
//!   clears it, so several entries carry it after a pair switch.)
//!
//! Then re-run the loopback tests at the bottom of this file (`cargo test --features webrtc
//! webrtc::tests`).

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data::data_channel::DataChannel as DetachedDataChannel;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::time::{timeout, timeout_at, Instant};
use url::Url;

use crate::config;
use crate::protobuf::Message;
use crate::sodiumoxide::crypto::secretbox::Key;
use crate::ResultType;

#[derive(Clone, Debug, PartialEq, Eq)]
enum WebRTCConnectionState {
    Pending,
    Open,
    Closed(String),
}

pub struct WebRTCStream {
    pc: Arc<RTCPeerConnection>,
    stream: Arc<Mutex<Arc<RTCDataChannel>>>,
    state_notify: watch::Receiver<WebRTCConnectionState>,
    local_ice_rx: Arc<StdMutex<Option<mpsc::UnboundedReceiver<String>>>>,
    session_key: String,
    send_timeout: u64,
    // Built with Relay-only ICE policy (force_relay): every selected pair goes through TURN.
    relay_only: bool,
    // Detached data channel, cached after the first `detach()` so send/recv do not re-lock and
    // re-fetch it per message. Shared across clones; `detach()` is idempotent.
    detached: Arc<Mutex<Option<Arc<DetachedDataChannel>>>>,
    // Serialize a complete logical message across clones. Each fragment is a separate SCTP
    // message, so serializing only individual writes would allow two large messages to interleave.
    send_gate: Arc<Semaphore>,
    // Receive-side reassembly state, behind the Arc rather than in the future so a cancelled
    // `next()` does not lose the partial message. SINGLE READER ONLY: reassembly spans calls, and
    // the fragment header carries no length or sequence number, so two readers splice unrelated
    // fragments into one `acc` and produce a well-formed, undetectably wrong message. Every
    // consumer today reads from one task; keep it that way (this is why no API hands out a clone
    // that outlives its `Stream`).
    recv_state: Arc<Mutex<RecvState>>,
    // True once the controller has completed the RustDesk identity binding (DTLS fingerprint
    // matched to the signed peer id, via `set_key`). DTLS always encrypts; this flag mirrors TCP's
    // "secured after key exchange" so key-less / unbound WebRTC is not shown as peer-authenticated.
    peer_verified: Arc<AtomicBool>,
}

#[derive(Default)]
struct RecvState {
    // Accumulated payload of the logical message currently being reassembled. Only multi-fragment
    // messages reach it; a message that arrives whole is split straight out of `scratch`.
    acc: BytesMut,
    // Read buffer, refilled in `SCRATCH_REFILL` chunks rather than per read. A whole-message
    // fragment is handed to the caller with `split_to`, which shares this allocation instead of
    // copying, so the buffer is consumed from the front and re-initialized only when what is left
    // can no longer hold one fragment — amortizing that cost over many small messages.
    scratch: BytesMut,
}

// The SCTP data channel's 65536-byte max message size is handled by
// splitting a logical message into fragments carrying a 1-byte header. Fragment payload is kept
// well under the limit so header+payload never reaches the exact-65536 boundary that the
// receiver's reassembly would truncate with data loss.
const MAX_FRAGMENT_PAYLOAD: usize = 60000;
/// Receive scratch size: must be >= 1 (fragment header) + `MAX_FRAGMENT_PAYLOAD` and fit the
/// negotiated SCTP max message size.
const RECV_BUF_SIZE: usize = 64 * 1024;
/// How much read buffer to initialize at a time. Whole messages are split out of it without
/// copying, so it is consumed rather than reused; refilling in chunks spreads the one cost that
/// remains — zeroing — across every small message that fits. Slices handed to the caller keep the
/// whole chunk alive, so this trades a bounded amount of retention for the copy.
const SCRATCH_REFILL: usize = 4 * RECV_BUF_SIZE;
/// Fragment header byte: more fragments follow for this logical message.
const FRAG_MORE: u8 = 1;
/// Fragment header byte: final (or only) fragment of a logical message.
const FRAG_END: u8 = 0;
/// Largest logical message this transport will send or reassemble.
///
/// Held at parity with TCP on purpose. A transport-specific ceiling would be a trap: the same
/// session moves between WebRTC and the relay, so a message under TCP's limit but over this one
/// would work on one path and kill the connection on the other — and it would bite hardest on
/// exactly the large messages (a keyframe, a big clipboard image) that a direct path exists to
/// carry. Whatever the right maximum is, both transports need the same one.
///
/// That leaves a real exposure, shared with TCP and not created here: the cap is the memory an
/// unauthenticated peer can make a receiver hold, and the answerer runs before any password
/// check. TCP is no better off — `BytesCodec::new` leaves `max_packet_length` at `usize::MAX`,
/// so its only bound is the 30-bit length field in the frame header. Tightening it belongs in
/// one change across both paths, with a number measured against real traffic rather than
/// guessed; until then this at least holds the peak to the cap instead of twice it.
const MAX_RECV_MESSAGE: usize = crate::bytes_codec::MAX_FRAME_LENGTH;
// use 3 public STUN servers to find out the NAT type, 2 must be the same address but different ports
// https://stackoverflow.com/questions/72805316/determine-nat-mapping-behaviour-using-two-stun-servers
// luckily nextcloud supports two ports for STUN
// unluckily webrtc-rs does not use the same port to do the STUN request
static DEFAULT_ICE_SERVERS: [&str; 3] = [
    "stun:stun.cloudflare.com:3478",
    "stun:stun.nextcloud.com:3478",
    "stun:stun.nextcloud.com:443",
];

lazy_static::lazy_static! {
    static ref SESSIONS: Arc::<Mutex<HashMap<String, WebRTCStream>>> = Default::default();
}

impl Clone for WebRTCStream {
    fn clone(&self) -> Self {
        WebRTCStream {
            pc: self.pc.clone(),
            stream: self.stream.clone(),
            state_notify: self.state_notify.clone(),
            local_ice_rx: self.local_ice_rx.clone(),
            session_key: self.session_key.clone(),
            send_timeout: self.send_timeout,
            relay_only: self.relay_only,
            detached: self.detached.clone(),
            send_gate: self.send_gate.clone(),
            recv_state: self.recv_state.clone(),
            peer_verified: self.peer_verified.clone(),
        }
    }
}

impl WebRTCStream {
    #[inline]
    fn get_remote_offer(endpoint: &str) -> ResultType<String> {
        // Ensure the endpoint starts with the "webrtc://" prefix
        if !endpoint.starts_with("webrtc://") {
            return Err(
                Error::new(ErrorKind::InvalidInput, "Invalid WebRTC endpoint format").into(),
            );
        }

        // Extract the Base64-encoded SDP part
        let encoded_sdp = &endpoint["webrtc://".len()..];
        // Decode the Base64 string
        let decoded_bytes = BASE64_STANDARD
            .decode(encoded_sdp)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Failed to decode Base64 SDP"))?;
        Ok(String::from_utf8(decoded_bytes).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "Failed to convert decoded bytes to UTF-8",
            )
        })?)
    }

    #[inline]
    fn sdp_to_endpoint(sdp: &str) -> String {
        let encoded_sdp = BASE64_STANDARD.encode(sdp);
        format!("webrtc://{}", encoded_sdp)
    }

    // Envelope JSON key carrying the local description's ICE transport policy, alongside the
    // RTCSessionDescription fields (see `get_local_endpoint_trickle`).
    // `'static` spelled out: an elided lifetime here is a warn-by-default future hard error on
    // the 1.75 toolchain CI pins (elided_lifetimes_in_associated_constant).
    const ICE_POLICY_KEY: &'static str = "ice_policy";
    const ICE_POLICY_ALL: &'static str = "all";

    #[inline]
    fn get_key_for_sdp(sdp: &RTCSessionDescription) -> ResultType<String> {
        let binding = sdp.unmarshal()?;
        let Some(fingerprint) = binding.attribute("fingerprint") else {
            // find fingerprint attribute in media descriptions
            for media in &binding.media_descriptions {
                if media.media_name.media != "application" {
                    continue;
                }
                if let Some(fp) = media
                    .attributes
                    .iter()
                    .find(|x| x.key == "fingerprint")
                    .and_then(|x| x.value.clone())
                {
                    return Ok(fp);
                }
            }
            return Err(anyhow::anyhow!("SDP fingerprint attribute not found"));
        };
        Ok(fingerprint.to_string())
    }

    /// Process-local SESSIONS-map key: the DTLS fingerprint prefixed by role. An offerer and an
    /// answerer that share a fingerprint (a single process connecting to its own id) would
    /// otherwise collide, handing the offerer back as the answerer. The wire-level `session_key`
    /// used for ICE-candidate routing stays the bare fingerprint so both peers still match.
    #[inline]
    fn cache_key(fingerprint: &str, is_offerer: bool) -> String {
        format!(
            "{}:{}",
            if is_offerer { "offer" } else { "answer" },
            fingerprint
        )
    }

    /// Reject a data channel from inside `on_data_channel`, where closing it directly does not
    /// work.
    ///
    /// webrtc-rs runs this handler to completion BEFORE `handle_open` binds the SCTP stream, so
    /// at this point `close()` only flips the ready state and returns — no stream reset — and
    /// `handle_open` then sets it back to Open. With detached channels no read loop is spawned
    /// either, so a channel refused here would stay open and undrained, and its queued bytes
    /// count against the association-wide receive window: about a megabyte written into an
    /// ignored channel stalls the one carrying the session. Close from the channel's own
    /// `on_open` instead, which runs once the stream exists.
    fn close_unbound_channel(dc: Arc<RTCDataChannel>) {
        let dc_for_close = dc.clone();
        dc.on_open(Box::new(move || {
            let dc = dc_for_close.clone();
            Box::pin(async move {
                if let Err(err) = dc.close().await {
                    log::debug!("failed to close rejected data channel: {}", err);
                }
            })
        }));
    }

    /// Whether a `SESSIONS` entry may be handed to a caller asking for `force_relay`.
    ///
    /// A hit returns a pc built for the FIRST caller, and two of its properties belong to this
    /// caller instead: the ICE policy (`rendezvous_mediator` recomputes relay-only per PunchHole,
    /// so a replayed offer wanting Relay-only must not get an All-policy pc free to pick a direct
    /// pair), and liveness (the state handler latches Closed and closes the stream before it
    /// reaches SESSIONS to evict, so the map briefly holds dead entries). `peer_verified` stays
    /// shared on purpose: it is a fact about the DTLS certificate the entry is keyed by.
    ///
    /// Both the lookup and the insert-time duplicate check must use this — they read the same key,
    /// so a test applied at only one of them is not applied at all.
    fn is_reusable_for(&self, force_relay: bool) -> bool {
        self.relay_only == force_relay
            && !matches!(
                *self.state_notify.borrow(),
                WebRTCConnectionState::Closed(_)
            )
    }

    #[inline]
    fn get_key_for_sdp_json(sdp_json: &str) -> ResultType<String> {
        if sdp_json.is_empty() {
            return Ok("".to_string());
        }
        let sdp = serde_json::from_str::<RTCSessionDescription>(sdp_json)?;
        Self::get_key_for_sdp(&sdp)
    }

    #[inline]
    async fn get_key_for_peer(pc: &Arc<RTCPeerConnection>, is_local: bool) -> ResultType<String> {
        let Some(desc) = (match is_local {
            true => pc.local_description().await,
            false => pc.remote_description().await,
        }) else {
            return Err(anyhow::anyhow!("PeerConnection description is not set"));
        };
        Self::get_key_for_sdp(&desc)
    }

    #[inline]
    fn get_ice_server_from_url(url: &str) -> Option<RTCIceServer> {
        let u = Url::parse(url).ok()?;
        if !matches!(u.scheme(), "turn" | "turns" | "stun" | "stuns") {
            return None;
        }
        // Two spellings are accepted, and they parse very differently:
        //
        // - `turn://user:pass@host:port` — non-standard, but the only form that can carry
        //   credentials. `url` sees an authority and fills host/port/username/password.
        // - `turn:host:port` — the RFC 7065 form users actually copy from TURN docs. These
        //   schemes are not special and there is no `//`, so `url` makes it cannot-be-a-base:
        //   `host_str()` is None and the whole `host:port` lands in the path. Reading it back
        //   out is what makes this form work at all; it previously produced a hostless
        //   `turn::3478` that no ICE agent can resolve — while still satisfying
        //   `has_turn_server()`, so a force_relay peer connection was built against it and
        //   could only ever time out.
        let (host, port) = match u.host_str() {
            Some(host) => (host.to_owned(), u.port().unwrap_or(3478)),
            None => Self::split_host_port(u.path())?,
        };
        if host.is_empty() {
            return None;
        }
        let username = u.username().to_string();
        let credential = u.password().unwrap_or_default().to_string();
        // A TURN server without credentials is not merely useless: webrtc-rs validates every
        // configured server in `new_peer_connection`, so one credential-less entry makes EVERY
        // peer connection fail — including plain non-relay ones that never wanted TURN. The
        // RFC 7065 spelling has nowhere to put credentials, so drop such entries here rather
        // than let them poison the whole configuration; `turn://user:pass@host:port` carries them.
        if matches!(u.scheme(), "turn" | "turns") && (username.is_empty() || credential.is_empty())
        {
            log::warn!(
                "Ignoring TURN server without credentials: {}:{}:{} (use {}://user:pass@host:port)",
                u.scheme(),
                host,
                port,
                u.scheme()
            );
            return None;
        }
        Some(RTCIceServer {
            urls: vec![format!("{}:{}:{}", u.scheme(), host, port)],
            username,
            credential,
            ..Default::default()
        })
    }

    /// Split `host[:port]` from an RFC 7065 URL path, defaulting the port. Bracketed IPv6
    /// literals keep their brackets, which is the form webrtc-rs re-parses.
    fn split_host_port(path: &str) -> Option<(String, u16)> {
        let rest = path.split(['?', '#']).next().unwrap_or_default();
        if rest.is_empty() {
            return None;
        }
        if let Some(after_open) = rest.strip_prefix('[') {
            let (host, tail) = after_open.split_once(']')?;
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(3478);
            return Some((format!("[{host}]"), port));
        }
        // An unbracketed IPv6 literal has no unambiguous split point — `2001:db8::1` would be cut
        // at its last colon into host `2001:db8:` port `1` — so require the bracketed form for
        // those rather than emit a host webrtc-ice cannot resolve.
        if rest.matches(':').count() > 1 {
            log::warn!("Ignoring ICE server {rest}: bracket IPv6 literals as [addr]:port");
            return None;
        }
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => match port.parse() {
                Ok(port) => Some((host.to_owned(), port)),
                // A port that is present but unusable is a typo, not a host: folding it back in
                // would produce `host:99999:3478`, which webrtc-ice rejects outright — taking
                // every peer connection down with it, not just this server.
                Err(_) => {
                    log::warn!("Ignoring ICE server {rest}: invalid port");
                    None
                }
            },
            _ => Some((rest.to_owned(), 3478)),
        }
    }

    /// Whether the ICE configuration contains a usable TURN server. A Relay-policy peer
    /// connection (force_relay) can only gather relay candidates, so without a TURN server it can
    /// never connect — callers use this to skip building a guaranteed-dead pc.
    pub fn has_turn_server() -> bool {
        // `get_ice_server_from_url` is what makes a bare scheme test sufficient: it drops entries
        // with no host and TURN entries with no credentials, i.e. exactly the ones that would
        // answer `true` here while being unusable — which is worse than answering `false`, since
        // the caller skips its "don't build a guaranteed-dead Relay-only pc" guard on our word.
        Self::get_ice_servers().iter().any(|s| {
            s.urls
                .iter()
                .any(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        })
    }

    #[inline]
    fn get_ice_servers() -> Vec<RTCIceServer> {
        Self::parse_ice_servers(&config::Config::get_option(
            config::keys::OPTION_ICE_SERVERS,
        ))
    }

    /// Split out from `get_ice_servers` so parsing can be exercised without touching the
    /// process-global, on-disk-persisted option — the tests run in parallel threads of one
    /// process, so a test that rewrote it raced every peer connection another test was building.
    fn parse_ice_servers(cfg: &str) -> Vec<RTCIceServer> {
        let mut ice_servers = Vec::new();
        let mut has_stun = false;

        for url in cfg.split(',').map(str::trim) {
            if let Some(ice_server) = Self::get_ice_server_from_url(url) {
                // Detect STUN in user config
                if ice_server
                    .urls
                    .iter()
                    .any(|u| u.starts_with("stun:") || u.starts_with("stuns:"))
                {
                    has_stun = true;
                }

                ice_servers.push(ice_server);
            }
        }

        // If there is no STUN (either TURN-only or empty config) → prepend defaults
        if !has_stun {
            ice_servers.insert(
                0,
                RTCIceServer {
                    urls: DEFAULT_ICE_SERVERS.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
            );
        }
        ice_servers
    }

    pub async fn new(
        remote_endpoint: &str,
        force_relay: bool,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        // The endpoint contains a Base64-encoded SDP with host addresses and live ICE
        // credentials. Log only its size so debug logs cannot disclose that information.
        log::debug!(
            "New webrtc stream (remote endpoint: {} bytes)",
            remote_endpoint.len()
        );
        let remote_offer = if remote_endpoint.is_empty() {
            "".into()
        } else {
            Self::get_remote_offer(remote_endpoint)?
        };

        let mut key = Self::get_key_for_sdp_json(&remote_offer)?;
        let start_local_offer = remote_offer.is_empty();
        if !key.is_empty() {
            let cached = {
                let sessions_lock = SESSIONS.lock().await;
                sessions_lock
                    .get(&Self::cache_key(&key, start_local_offer))
                    .cloned()
            };
            if let Some(cached_stream) = cached {
                if cached_stream.is_reusable_for(force_relay) {
                    log::debug!("Start webrtc with cached peer");
                    return Ok(cached_stream);
                }
                log::debug!(
                    "Ignoring cached webrtc peer (relay_only {}, wanted {})",
                    cached_stream.relay_only,
                    force_relay
                );
            }
        }
        // Create a SettingEngine and enable Detach
        let mut s = SettingEngine::default();
        s.detach_data_channels();
        s.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);

        // Create the API object
        let api = APIBuilder::new().with_setting_engine(s).build();

        // Prepare the configuration, get ICE servers from config
        let config = RTCConfiguration {
            ice_servers: Self::get_ice_servers(),
            ice_transport_policy: if force_relay {
                RTCIceTransportPolicy::Relay
            } else {
                RTCIceTransportPolicy::All
            },
            ..Default::default()
        };

        let (notify_tx, notify_rx) = watch::channel(WebRTCConnectionState::Pending);
        let (ice_tx, ice_rx) = mpsc::unbounded_channel::<String>();
        // Create a new RTCPeerConnection
        let pc = Arc::new(api.new_peer_connection(config).await?);
        // This closure is the only owner of the ICE-candidate sender, and `on_*` handlers live
        // inside the pc: nothing clears them — not `RTCPeerConnection::close`, not the ICE
        // gatherer's own close — so the sender outlives `close()` and every `SESSIONS` eviction.
        // The receiver therefore never sees the channel close, and the forwarder task this API
        // asks callers to write (`while let Some(c) = rx.recv().await { peer.add_remote_ice(..) }`
        // with a stream clone moved in) parks on `recv()` forever, holding the pc alive with it:
        // one leaked task plus one leaked peer connection per connection. The terminal-state
        // handler below drops this closure to break that; see the note there.
        let local_ice_tx = ice_tx.clone();
        pc.on_ice_candidate(Box::new(move |candidate| {
            let local_ice_tx = local_ice_tx.clone();
            Box::pin(async move {
                let Some(candidate) = candidate else {
                    return;
                };
                match candidate.to_json() {
                    Ok(candidate) => match serde_json::to_string(&candidate) {
                        Ok(candidate_json) => {
                            let _ = local_ice_tx.send(candidate_json);
                        }
                        Err(err) => {
                            log::warn!("failed to serialize local ICE candidate: {}", err);
                        }
                    },
                    Err(err) => {
                        log::warn!("failed to convert local ICE candidate to JSON: {}", err);
                    }
                }
            })
        }));

        let bootstrap_dc = if start_local_offer {
            let dc_open_notify = notify_tx.clone();
            // Create a data channel with label "bootstrap"
            let dc = match pc.create_data_channel("bootstrap", None).await {
                Ok(dc) => dc,
                Err(e) => {
                    // Close before propagating: the pc is live and would otherwise leak.
                    pc.close().await.ok();
                    return Err(e.into());
                }
            };
            dc.on_open(Box::new(move || {
                log::debug!("Local data channel bootstrap open.");
                let _ = dc_open_notify.send(WebRTCConnectionState::Open);
                Box::pin(async {})
            }));
            dc
        } else {
            // Wait for the data channel to be created by the remote peer
            // Here we create a dummy data channel to satisfy the type system
            Arc::new(RTCDataChannel::default())
        };

        let stream = Arc::new(Mutex::new(bootstrap_dc));
        if !start_local_offer {
            // Register data channel creation handling
            let dc_open_notify = notify_tx.clone();
            let stream_for_dc = stream.clone();
            // The remote may open any number of channels; only the first is ever bound.
            let dc_bound = Arc::new(AtomicBool::new(false));
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let d_label = dc.label().to_owned();
                let dc_open_notify2 = dc_open_notify.clone();
                let stream_for_dc_clone = stream_for_dc.clone();
                let dc_bound = dc_bound.clone();
                Box::pin(async move {
                    // Reassembly spans data-channel messages, so it is sound only on an ordered,
                    // fully-reliable channel: the 1-byte fragment header carries no sequence
                    // number, so a reorder splices fragments into a well-formed but wrong
                    // message, and a dropped fragment merges two messages instead of erroring.
                    // webrtc-rs derives these parameters entirely from the REMOTE's DCEP OPEN
                    // (`channel_type` picks ordered / max_retransmits / max_packet_life_time),
                    // and this pc is built from an unauthenticated offer, so the peer would
                    // otherwise choose our reassembly's correctness conditions for us.
                    if !dc.ordered()
                        || dc.max_retransmits().is_some()
                        || dc.max_packet_lifetime().is_some()
                    {
                        log::warn!(
                            "Rejecting WebRTC data channel {}: not ordered and fully reliable",
                            d_label
                        );
                        Self::close_unbound_channel(dc);
                        return;
                    }
                    // Bind the first channel only. `detached` caches the first detached handle
                    // for the life of the stream, so rebinding would leave teardown closing a
                    // channel that send/recv no longer use; worse, a second channel's `on_open`
                    // would push Open onto the same watch and re-arm a session already latched
                    // Closed — and that watch gates both `send_bytes_inner` and `next()`.
                    if dc_bound.swap(true, Ordering::SeqCst) {
                        log::warn!("Ignoring extra WebRTC data channel {}", d_label);
                        Self::close_unbound_channel(dc);
                        return;
                    }
                    log::debug!("Remote data channel {} ready", d_label);
                    let mut stream_lock = stream_for_dc_clone.lock().await;
                    *stream_lock = dc.clone();
                    drop(stream_lock);
                    dc.on_open(Box::new(move || {
                        let _ = dc_open_notify2.send(WebRTCConnectionState::Open);
                        Box::pin(async {})
                    }));
                })
            }));
        }

        // This will notify you when the peer has connected/disconnected
        let stream_for_close = stream.clone();
        // Weak, not strong: a handler stored inside the pc that captured a strong
        // `Arc<RTCPeerConnection>` forms a pc -> internal -> handler -> pc cycle that `close()`
        // never breaks (it only fires the handler) and no `Drop` clears, permanently leaking every
        // pc and the ICE-candidate sender's forwarding task. Upgrade inside the handler; if the pc
        // is already gone there is nothing left in SESSIONS to evict.
        let pc_for_close = Arc::downgrade(&pc);
        pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            let stream_for_close2 = stream_for_close.clone();
            let on_connection_notify = notify_tx.clone();
            let pc_for_close2 = pc_for_close.clone();
            Box::pin(async move {
                log::debug!("WebRTC session peer connection state: {}", s);
                match s {
                    // `Disconnected` is a transient, recoverable ICE state (webrtc-ice fires it
                    // after ~5s without consent and returns to `Connected` when traffic resumes).
                    // Only tear down on the terminal states so a short network blip (Wi-Fi roam,
                    // sleep/wake, cell handover) does not permanently kill an established session.
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                        let _ =
                            on_connection_notify.send(WebRTCConnectionState::Closed(s.to_string()));
                        log::debug!("WebRTC session closing due to {}", s);
                        let _ = stream_for_close2.lock().await.close().await;
                        log::debug!("WebRTC session stream closed");

                        let Some(pc_for_close2) = pc_for_close2.upgrade() else {
                            return;
                        };

                        // Drop the ICE-candidate handler, and with it the only sender for the
                        // local-candidate channel. Nothing else ever will: `close()` clears no
                        // handler, so the receiver would stay open forever and a caller's
                        // forwarder task would park on `recv()` holding a stream clone — keeping
                        // this pc alive past its own teardown. Replacing the handler with a
                        // no-op closes the channel, the forwarder's loop ends, and its clone
                        // goes with it. Gathering is over by this state anyway.
                        pc_for_close2.on_ice_candidate(Box::new(|_| Box::pin(async {})));

                        let mut sessions_lock = SESSIONS.lock().await;
                        match Self::get_key_for_peer(&pc_for_close2, start_local_offer).await {
                            Ok(fingerprint) => {
                                let k = Self::cache_key(&fingerprint, start_local_offer);
                                // Only evict if the cached entry IS this pc: a duplicate offer
                                // resolves to the same key, and closing the discarded duplicate pc
                                // must not remove the live winner sharing that key.
                                if sessions_lock
                                    .get(&k)
                                    .is_some_and(|s| Arc::ptr_eq(&s.pc, &pc_for_close2))
                                {
                                    sessions_lock.remove(&k);
                                    log::debug!("WebRTC session removed key: {}", k);
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to extract key for peer during session cleanup: {:?}",
                                    e
                                );
                                // Fallback: try to remove any session associated with this peer connection
                                let keys_to_remove: Vec<String> = sessions_lock
                                    .iter()
                                    .filter_map(|(key, session)| {
                                        if Arc::ptr_eq(&session.pc, &pc_for_close2) {
                                            Some(key.clone())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                for k in keys_to_remove {
                                    sessions_lock.remove(&k);
                                    log::debug!("WebRTC session removed by fallback key: {}", k);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            })
        }));

        // process offer/answer
        //
        // Trickle ICE: this block is local-only work (pc construction, DTLS keygen, SDP marshal),
        // no gathering wait. The controlled side awaits answer creation inline on its punch-reply
        // critical path, so adding a network wait here would delay every hole punch.
        // A failure below leaves a live pc whose state handler only fires on a terminal ICE state,
        // so a bare `?`-drop leaks it — remotely triggerable via a crafted `type:"answer"` offer
        // that passes the pre-check but fails `set_remote_description`. Close before propagating.
        let offer_answer: ResultType<String> = async {
            if start_local_offer {
                let sdp = pc.create_offer(None).await?;
                pc.set_local_description(sdp.clone()).await?;
                // SDP carries host/srflx IPs and ICE ufrag/pwd; log only its size, not the body.
                log::debug!("local offer SDP built ({} bytes)", sdp.sdp.len());
                let k = Self::get_key_for_sdp(&sdp)?;
                log::debug!("Start webrtc with local key: {}", k);
                Ok(k)
            } else {
                let sdp = serde_json::from_str::<RTCSessionDescription>(&remote_offer)?;
                pc.set_remote_description(sdp.clone()).await?;
                let answer = pc.create_answer(None).await?;
                pc.set_local_description(answer).await?;
                log::debug!("remote offer SDP received ({} bytes)", sdp.sdp.len());
                let k = Self::get_key_for_sdp(&sdp)?;
                log::debug!("Start webrtc with remote key: {}", k);
                Ok(k)
            }
        }
        .await;
        key = match offer_answer {
            Ok(k) => k,
            Err(e) => {
                pc.close().await.ok();
                return Err(e);
            }
        };

        let webrtc_stream = Self {
            pc,
            stream,
            state_notify: notify_rx,
            local_ice_rx: Arc::new(StdMutex::new(Some(ice_rx))),
            session_key: key.clone(),
            send_timeout: ms_timeout,
            relay_only: force_relay,
            detached: Arc::new(Mutex::new(None)),
            send_gate: Arc::new(Semaphore::new(1)),
            recv_state: Arc::new(Mutex::new(RecvState::default())),
            peer_verified: Arc::new(AtomicBool::new(false)),
        };
        // Insert into the session cache, but never `await pc.close()` while holding this lock:
        // `close()` fires the peer-connection-state handler inline, which itself locks SESSIONS,
        // self-deadlocking the whole process. Resolve any duplicate off-lock.
        let cache_key = Self::cache_key(&key, start_local_offer);
        let duplicate = {
            let mut final_lock = SESSIONS.lock().await;
            // Same admissibility test as the lookup above, or that lookup is dead code: an entry
            // rejected there is still in the map when we get here, so returning it unconditionally
            // would discard the pc we just built precisely because the cached one was unusable.
            match final_lock.get(&cache_key) {
                Some(session) if session.is_reusable_for(force_relay) => Some(session.clone()),
                _ => {
                    final_lock.insert(cache_key, webrtc_stream.clone());
                    None
                }
            }
        };
        if let Some(session) = duplicate {
            // A concurrent `new()` already cached an equivalent stream; discard this pc's
            // resources (off-lock) and return the cached one.
            webrtc_stream.close().await;
            return Ok(session);
        }
        Ok(webrtc_stream)
    }

    /// One-shot endpoint: waits for ICE gathering so the SDP already carries the candidates.
    /// The wait is deliberately unbounded — a deadline here would return a half-gathered SDP and
    /// defeat the contract; callers needing one should wrap the call or use the trickle variant,
    /// which both rustdesk signaling paths do. Remaining callers are the loopback tests and
    /// `examples/webrtc.rs`, neither of which bounds it.
    #[inline]
    pub async fn get_local_endpoint(&self) -> ResultType<String> {
        // Preserve the original one-shot endpoint contract: callers that only exchange this SDP
        // do not have a separate path for `take_local_ice_rx`, so their endpoint must contain the
        // gathered host/srflx/relay candidates.
        let mut gather_complete = self.pc.gathering_complete_promise().await;
        let _gathering_channel_closed = gather_complete.recv().await;
        self.get_local_endpoint_trickle().await
    }

    /// Return the current local description immediately for callers that signal candidates via
    /// `take_local_ice_rx`. Unlike `get_local_endpoint`, this does not wait for ICE gathering.
    #[inline]
    pub async fn get_local_endpoint_trickle(&self) -> ResultType<String> {
        if let Some(local_desc) = self.pc.local_description().await {
            let sdp = if self.relay_only {
                serde_json::to_string(&local_desc)?
            } else {
                // Declare the ICE transport policy inside the envelope. The receiver of an
                // offer that arrives with force_relay set must know whether it may answer
                // with full ICE (relay forced by the transport, e.g. WebSocket signaling)
                // or must stay Relay-only + TURN-gated (relay by policy) — and the envelope
                // is the offer's own property, so it rides here rather than in a proto
                // field the rendezvous server would have to forward. An extra key is
                // invisible to older peers: serde ignores unknown fields when parsing
                // RTCSessionDescription, so absence — not an error — is the old semantics.
                let mut v = serde_json::to_value(&local_desc)?;
                v[Self::ICE_POLICY_KEY] = serde_json::Value::from(Self::ICE_POLICY_ALL);
                serde_json::to_string(&v)?
            };
            let endpoint = Self::sdp_to_endpoint(&sdp);
            Ok(endpoint)
        } else {
            Err(anyhow::anyhow!("Local desc is not set"))
        }
    }

    /// Whether the peer's endpoint declares it was built with ICE transport policy `all`
    /// (W3C RTCIceTransportPolicy), i.e. it gathers host/srflx/relay candidates and a direct
    /// pair may form even though the request carries force_relay. Absent key, foreign format
    /// or parse failure all mean "not declared" — the old Relay-only reading.
    pub fn endpoint_declares_all_ice(endpoint: &str) -> bool {
        let Ok(sdp_json) = Self::get_remote_offer(endpoint) else {
            return false;
        };
        serde_json::from_str::<serde_json::Value>(&sdp_json)
            .ok()
            .and_then(|v| {
                v.get(Self::ICE_POLICY_KEY)?
                    .as_str()
                    .map(|p| p == Self::ICE_POLICY_ALL)
            })
            .unwrap_or(false)
    }

    #[inline]
    pub async fn set_remote_endpoint(&self, endpoint: &str) -> ResultType<()> {
        let offer = Self::get_remote_offer(endpoint)?;
        log::debug!("WebRTC set remote sdp ({} bytes)", offer.len());
        let sdp = serde_json::from_str::<RTCSessionDescription>(&offer)?;
        self.pc.set_remote_description(sdp).await?;
        Ok(())
    }

    /// DTLS certificate fingerprint of the local description (this endpoint's own cert).
    #[inline]
    pub async fn local_dtls_fingerprint(&self) -> ResultType<String> {
        Self::get_key_for_peer(&self.pc, true).await
    }

    /// DTLS certificate fingerprint of the remote description (the peer's cert). webrtc-rs
    /// verifies the negotiated peer certificate against this fingerprint during the DTLS
    /// handshake, so once the channel is open a matching fingerprint identifies the peer's cert.
    #[inline]
    pub async fn remote_dtls_fingerprint(&self) -> ResultType<String> {
        Self::get_key_for_peer(&self.pc, false).await
    }

    /// Whether the connection runs through a TURN relay; feeds the UI's direct/relayed flag.
    /// Under Relay policy the answer is known by construction, so that arm returns `Some(true)`
    /// without consulting ICE — including before a pair is selected, unlike the `None` the other
    /// arm returns then. Both callers ask post-connection, where the arms agree; making the relay
    /// arm await a pair would only add a stats round trip.
    pub async fn is_relayed(&self) -> Option<bool> {
        if self.relay_only {
            return Some(true);
        }
        let dtls = self.pc.sctp().transport();
        let pair = dtls.ice_transport().get_selected_candidate_pair().await?;

        // Answer from the selected pair, not from the stats report's `nominated` flag: in
        // webrtc-ice that flag is sticky per checklist entry (set on nomination, never cleared —
        // a pair switch only clears the agent's own `nominated_pair` slot), and the report
        // enumerates the whole checklist. After an ICE switch, or on a controlled agent that saw
        // USE-CANDIDATE more than once, several entries carry it and `HashMap::values()` order
        // decides the answer — which can differ between two calls in one session.
        //
        // 0.13 keeps the pair's candidates private, so read the types out of its `Display`:
        // "(local) {protocol} {typ} {addr}:{port}{related} <-> (remote) ...". Positionally, not
        // by substring — an address must not be able to pass for a candidate type. See the
        // upgrade checklist: 0.17+ exposes the fields and this parse goes away.
        let relay = RTCIceCandidateType::Relay.to_string();
        Some(
            pair.to_string()
                .split(" <-> ")
                .filter_map(|side| side.split_whitespace().nth(2))
                .any(|typ| typ == relay),
        )
    }

    #[inline]
    pub fn take_local_ice_rx(&self) -> Option<mpsc::UnboundedReceiver<String>> {
        self.local_ice_rx.lock().ok().and_then(|mut rx| rx.take())
    }

    #[inline]
    pub async fn add_remote_ice_candidate(&self, candidate_json: &str) -> ResultType<()> {
        if candidate_json.is_empty() {
            return Ok(());
        }
        let candidate = serde_json::from_str::<RTCIceCandidateInit>(candidate_json)?;
        self.pc.add_ice_candidate(candidate).await?;
        Ok(())
    }

    #[inline]
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    pub async fn wait_connected(&mut self, ms: u64) -> ResultType<()> {
        if ms > 0 {
            match timeout(Duration::from_millis(ms), self.wait_for_connect_result()).await {
                Ok(result) => result?,
                Err(_) => return Err(anyhow::anyhow!("WebRTC wait_connected timeout")),
            }
        } else {
            self.wait_for_connect_result().await?;
        }
        Ok(())
    }

    /// Explicitly tear down the peer connection. Dropping the handle is not enough: `SESSIONS`
    /// holds a clone, so the pc and its ICE/DTLS resources survive until it happens to reach a
    /// terminal ICE state. Closing fires the state handler, which evicts the `SESSIONS` entry —
    /// callers that abandon a stream (e.g. an offerer that lost the transport race) must call it.
    #[inline]
    pub async fn close(&self) {
        self.pc.close().await.ok();
    }

    /// Tear the pc down on the runtime instead of awaiting it here, keeping `keep` alive until
    /// the teardown finishes.
    ///
    /// Every caller polls `next()` — and often `send_bytes` — inside a `tokio::select!`, so an
    /// `.await` on these paths is a cancellation point, and a competing arm (connection.rs and
    /// io_loop.rs both run a 1s timer next to the read) routinely wins one. That is fatal to a
    /// close: `RTCPeerConnection::close` latches `is_closed` before its first await and fires
    /// the state handler only at the very end, so a cancelled close leaves a pc no later
    /// `close()` can retry (they early-return on `is_closed`), whose `SESSIONS` entry — evicted
    /// only from that handler — is stranded for the life of the process, and whose
    /// `state_notify` never reaches `Closed`, leaving `wait_for_connect_result` reporting a live
    /// connection on a dead pc.
    ///
    /// `keep` carries anything whose lifetime must span the teardown rather than the caller's:
    /// the send path passes its logical-message permit, so no waiting clone can append to a
    /// partially-written fragment sequence while the close is still in flight.
    pub fn close_detached_with<T: Send + 'static>(&self, keep: T) {
        let pc = self.pc.clone();
        // Take the runtime handle explicitly rather than calling `tokio::spawn`: this also runs
        // from `Drop`, which can execute on a thread with no runtime, where a bare spawn panics —
        // and a panic in a destructor aborts the process. Without a handle the pc cannot be closed
        // here at all; it is released at process exit. (Catching a panic from `Handle::spawn`
        // during runtime shutdown is not an option: release builds set `panic = "abort"`.)
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::debug!("no tokio runtime available to close the WebRTC peer connection");
            return;
        };
        handle.spawn(async move {
            let _keep = keep;
            if let Err(err) = pc.close().await {
                log::debug!("WebRTC background close failed: {}", err);
            }
        });
    }

    #[inline]
    pub fn close_detached(&self) {
        self.close_detached_with(());
    }

    #[inline]
    pub fn set_raw(&mut self) {
        // not-supported
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        self.send_timeout = ms;
    }

    #[inline]
    pub fn set_key(&mut self, _key: Key) {
        // WebRTC traffic is DTLS-encrypted regardless; the secretbox key is unused.
        // Callers invoke set_key only after the controller has bound the DTLS fingerprint to the
        // verified peer identity (or the controlled side has completed the matching handshake).
        // Mark peer-verified so is_secured() matches TCP's post-key-exchange meaning.
        self.peer_verified.store(true, Ordering::Release);
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        self.peer_verified.load(Ordering::Acquire)
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        self.send_bytes(Bytes::from(msg)).await
    }

    #[inline]
    async fn wait_for_connect_result(&mut self) -> ResultType<()> {
        loop {
            match self.state_notify.borrow().clone() {
                WebRTCConnectionState::Open => return Ok(()),
                WebRTCConnectionState::Closed(reason) => {
                    return Err(anyhow::anyhow!("WebRTC connection closed: {}", reason));
                }
                WebRTCConnectionState::Pending => {}
            }
            self.state_notify.changed().await?;
        }
    }

    /// Fetch (and cache) the detached data channel. `detach()` is idempotent and returns a
    /// clone of the same underlying channel, so caching it just avoids re-locking per message.
    async fn detached_dc(&self) -> ResultType<Arc<DetachedDataChannel>> {
        {
            let cache = self.detached.lock().await;
            if let Some(dc) = cache.as_ref() {
                return Ok(dc.clone());
            }
        }
        let raw = self.stream.lock().await.clone();
        let dc = raw.detach().await?;
        let mut cache = self.detached.lock().await;
        // Another task may have cached it while we were detaching.
        if let Some(existing) = cache.as_ref() {
            return Ok(existing.clone());
        }
        *cache = Some(dc.clone());
        Ok(dc)
    }

    /// NOT cancel-safe: dropping this future mid-message (e.g. wrapping it in `select!`/`timeout`)
    /// can leave a partial fragment sequence on the wire, corrupting reassembly of every later
    /// message on this stream. A caller that abandons a send must treat the stream as dead and
    /// close it; the built-in `send_timeout` path below already does (it closes the pc).
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let send_timeout = self.send_timeout;
        let send_gate = self.send_gate.clone();
        // Bound the WHOLE send (wait-for-open, queueing behind another clone, every write) by
        // send_timeout: otherwise a write parks indefinitely on SCTP backpressure and
        // connection.rs's timer never runs. That parking is also what bounds sender memory —
        // PendingQueue admits 128 KiB and inflight is cwnd/rwnd-capped — so this timeout is the
        // TCP-send-timeout equivalent. See the checklist entry on send backpressure.
        if send_timeout > 0 {
            // Waiting for the connection to open is not this message's progress. Charging it to
            // the send clock meant that on the first send after signaling, a slow ICE/DTLS
            // completion ate most of the budget and the write inherited the remainder — then
            // timed out and closed a peer connection that was an RTT from working. Give it its
            // own budget and start the send clock once the channel is actually usable.
            timeout(
                Duration::from_millis(send_timeout),
                self.wait_for_connect_result(),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "WebRTC connect timeout"))??;

            let gate_deadline = Instant::now() + Duration::from_millis(send_timeout);
            let send_permit = match timeout_at(gate_deadline, send_gate.acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(err)) => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        format!("WebRTC send gate closed: {}", err),
                    )
                    .into());
                }
                Err(_) => {
                    // Deliberately no teardown: this task never held the permit, so all that
                    // happened is that another clone is legitimately mid-message. Closing from
                    // here would abort a healthy sender's fragment sequence — precisely the
                    // corruption the permit exists to prevent.
                    return Err(Error::new(ErrorKind::TimedOut, "WebRTC send gate timeout").into());
                }
            };
            // Fresh budget once the permit is held: queueing behind another clone's message is
            // not this message's progress, so charging it here meant a caller that only just lost
            // the gate race got a few milliseconds to write in — and then tore the whole peer
            // connection down for missing them. The narrower the miss, the more certain the
            // teardown, which is precisely backwards.
            let write_deadline = Instant::now() + Duration::from_millis(send_timeout);
            let mut desynced = false;
            match timeout_at(write_deadline, self.send_bytes_inner(bytes, &mut desynced)).await {
                // A write that failed part-way leaves the same orphaned prefix a timeout does, so
                // it needs the same teardown — and the same handoff of the permit, or a waiting
                // clone appends its message to that prefix while the close is still in flight.
                Ok(res) => {
                    if desynced {
                        self.close_detached_with(send_permit);
                    }
                    res
                }
                Err(_) => {
                    // Hand the logical-message permit to the teardown so no waiting clone can
                    // append a new message after a partially-written fragment sequence. Holding
                    // it across an awaited close would drop both on cancellation.
                    self.close_detached_with(send_permit);
                    Err(Error::new(ErrorKind::TimedOut, "WebRTC send timeout").into())
                }
            }
        } else {
            let send_permit = send_gate.acquire_owned().await.map_err(|err| {
                Error::new(
                    ErrorKind::BrokenPipe,
                    format!("WebRTC send gate closed: {}", err),
                )
            })?;
            let mut desynced = false;
            let res = self.send_bytes_inner(bytes, &mut desynced).await;
            if desynced {
                self.close_detached_with(send_permit);
            }
            res
        }
    }

    /// `desynced` is set when the failure left a partial fragment sequence on the wire, i.e. when
    /// the stream can no longer be made consistent and the caller must close it.
    async fn send_bytes_inner(&mut self, bytes: Bytes, desynced: &mut bool) -> ResultType<()> {
        // Same bound the receiver enforces, so we never emit a message a same-version peer
        // would have to kill the connection over.
        if bytes.len() > MAX_RECV_MESSAGE {
            return Err(Error::new(ErrorKind::InvalidInput, "Overflow").into());
        }
        self.wait_for_connect_result().await?;
        let dc = self.detached_dc().await?;
        let data = bytes.as_ref();
        let mut offset = 0;
        // Always emit at least one fragment (a lone FRAG_END header for an empty message), so a
        // zero-length data-channel message — which the receiver cannot distinguish from EOF — is
        // never sent.
        let mut wrote_any = false;
        loop {
            let end = (offset + MAX_FRAGMENT_PAYLOAD).min(data.len());
            let is_last = end >= data.len();
            let chunk = &data[offset..end];
            let mut framed = BytesMut::with_capacity(1 + chunk.len());
            framed.put_u8(if is_last { FRAG_END } else { FRAG_MORE });
            framed.put_slice(chunk);
            if let Err(err) = dc.write(&framed.freeze()).await {
                // A sequence that stops with fragments already on the wire leaves the peer's
                // accumulator holding a prefix that will never be terminated — and this framing
                // carries no length or sequence number for it to notice with, so the next message
                // is appended to the orphan and parsed as one corrupt frame. Report it so the
                // caller can tear the stream down while still holding the send permit; callers
                // wrap sends in allow_err! and keep going, so returning the error alone would
                // leave the corruption in place.
                *desynced = wrote_any;
                return Err(err.into());
            }
            wrote_any = true;
            offset = end;
            if is_last {
                break;
            }
        }
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Err(err) = self.wait_for_connect_result().await {
            self.close_detached();
            return Some(Err(Error::new(ErrorKind::Other, err.to_string())));
        }
        let dc = match self.detached_dc().await {
            Ok(dc) => dc,
            Err(err) => {
                self.close_detached();
                return Some(Err(Error::new(ErrorKind::Other, err.to_string())));
            }
        };
        // Held across `dc.read().await` on purpose, against the usual "no locks across await"
        // rule: it is what makes the single reader this reassembly requires (see the field) an
        // exclusion rather than a convention. Releasing it around the read would admit exactly
        // the second reader that corrupts `acc`. The cost — a would-be second reader blocking
        // until a packet arrives — is a state the design does not permit anyway.
        let mut st = self.recv_state.lock().await;
        loop {
            let RecvState { acc, scratch } = &mut *st;
            if scratch.len() < RECV_BUF_SIZE {
                scratch.resize(SCRATCH_REFILL, 0);
            }
            let n = match dc.read(&mut scratch[..RECV_BUF_SIZE]).await {
                Ok(n) => n,
                Err(err) => {
                    // Release the partial message, as the framing-violation paths below do: the
                    // buffer can hold up to the cap and `recv_state` outlives this call through
                    // the `SESSIONS` clone.
                    *acc = BytesMut::new();
                    self.close_detached();
                    return Some(Err(Error::new(
                        ErrorKind::Other,
                        format!("data channel read error: {}", err),
                    )));
                }
            };
            if n == 0 {
                // End of stream. Our own sender never produces this — every fragment carries at
                // least its header byte — but it is NOT exclusively a reset: webrtc-data maps the
                // StringEmpty/BinaryEmpty PPIDs to n == 0 as well, and `read` discards the flag
                // that would separate them, so a peer can also reach here by sending one empty
                // data-channel message. Both mean the same thing to us (this peer will send us
                // nothing more we can frame), so treat them alike, but do not report it as a
                // clean remote close: it is equally a peer that just violated the framing.
                log::debug!("WebRTC data channel ended (reset or empty message)");
                *acc = BytesMut::new();
                self.close_detached();
                return None;
            }
            // Two framing violations, both of which would otherwise be read as "more fragments":
            // an unrecognized header, and a FRAG_MORE carrying no payload. The latter is the
            // nastier one — it adds nothing to `acc`, so the MAX_FRAME_LENGTH cap below never
            // trips and the loop spins for as long as the peer keeps sending. `send_bytes_inner`
            // emits FRAG_MORE only for a full MAX_FRAGMENT_PAYLOAD chunk, so neither is reachable
            // from our own sender.
            let header = scratch[0];
            let bad = match header {
                FRAG_END => None,
                FRAG_MORE if n > 1 => None,
                FRAG_MORE => Some("FRAG_MORE fragment carries no payload".to_owned()),
                other => Some(format!(
                    "fragment header {other} is neither FRAG_END nor FRAG_MORE"
                )),
            };
            if let Some(why) = bad {
                *acc = BytesMut::new();
                self.close_detached();
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("WebRTC {why}"),
                )));
            }
            // Bound BEFORE growing, not after. This framing carries no length, so an oversize
            // message can only be discovered by accumulating it — unlike the TCP codec, which
            // rejects on the declared length before a single payload byte is buffered. Checking
            // after the append would make the peak the cap plus a fragment, and `BytesMut` grows
            // by reallocate-and-copy, so the final doubling would hold the old and new buffers at
            // once: ~2x the cap in RSS for a session that has produced no message at all.
            if acc.len() + (n - 1) > MAX_RECV_MESSAGE {
                // Release the buffer, don't just truncate it: by definition it is near the cap
                // here, and `recv_state` outlives this call through the `SESSIONS` clone.
                *acc = BytesMut::new();
                self.close_detached();
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    "WebRTC reassembled message exceeded maximum frame size",
                )));
            }
            // A message that arrived whole is handed over as a slice of the read buffer: no
            // allocation and no copy, which is every input event and most audio packets.
            if header == FRAG_END && acc.is_empty() {
                scratch.advance(1);
                return Some(Ok(scratch.split_to(n - 1)));
            }
            acc.extend_from_slice(&scratch[1..n]);
            if header == FRAG_END {
                let msg = std::mem::take(acc);
                return Some(Ok(msg));
            }
        }
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        match timeout(Duration::from_millis(ms), self.next()).await {
            Ok(res) => res,
            Err(_) => None,
        }
    }
}

pub fn is_webrtc_endpoint(endpoint: &str) -> bool {
    // use sdp base64 json string as endpoint, or prefix webrtc:
    endpoint.starts_with("webrtc://")
}

#[cfg(test)]
mod tests {
    use crate::webrtc::WebRTCStream;
    use crate::webrtc::{DEFAULT_ICE_SERVERS, FRAG_MORE, SESSIONS};
    use bytes::{BufMut, Bytes, BytesMut};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Barrier;
    use tokio::time::timeout;
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

    #[test]
    fn test_webrtc_ice_url() {
        let turn = WebRTCStream::get_ice_server_from_url("turn://123:321@example.com:3478")
            .expect("credentialed turn is usable");
        assert_eq!(turn.urls[0], "turn:example.com:3478");
        assert_eq!(turn.username, "123");
        assert_eq!(turn.credential, "321");

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123:321@example.com")
                .unwrap_or_default()
                .urls[0],
            "turn:example.com:3478"
        );

        // TURN without both halves of the credential is dropped rather than passed on:
        // webrtc-rs validates every configured server when the peer connection is built, so
        // one such entry fails EVERY connection, including those that never wanted TURN.
        for missing in [
            "turn://example.com:3478",
            "turn://example.com",
            "turn://123@example.com",
            "turns://example.com:5349",
            "turn:example.com:3478",
        ] {
            assert_eq!(
                WebRTCStream::get_ice_server_from_url(missing),
                None,
                "credential-less {missing} must not reach the configuration"
            );
        }

        // STUN needs no credentials, so both spellings stay usable.
        assert_eq!(
            WebRTCStream::get_ice_server_from_url("stun://example.com:3478")
                .unwrap_or_default()
                .urls[0],
            "stun:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("http://123:123@example.com:3478"),
            None
        );

        // RFC 7065 spelling (`scheme:host:port`, no authority) — what STUN/TURN docs hand out.
        // `url` cannot-be-a-base's it, so host and port come out of the path; getting this wrong
        // produced a hostless "stun::3478" no ICE agent can resolve.
        for (input, expected) in [
            ("stun:example.com:19302", "stun:example.com:19302"),
            ("stun:example.com", "stun:example.com:3478"),
            ("stun:[2001:db8::1]:19302", "stun:[2001:db8::1]:19302"),
            ("stun:[2001:db8::1]", "stun:[2001:db8::1]:3478"),
            (
                "stun:example.com:19302?transport=udp",
                "stun:example.com:19302",
            ),
        ] {
            assert_eq!(
                WebRTCStream::get_ice_server_from_url(input)
                    .unwrap_or_default()
                    .urls[0],
                expected,
                "parsing {input}"
            );
        }

        // Malformed entries are dropped, never repaired into something webrtc-ice will choke
        // on: a folded-in bad port ("host:99999:3478") or an unbracketed IPv6 split at its last
        // colon fails peer-connection construction outright, taking every server down with it.
        for bad in [
            "stun:",
            "stun:example.com:99999",
            "stun:example.com:abc",
            "stun:2001:db8::1",
        ] {
            assert_eq!(
                WebRTCStream::get_ice_server_from_url(bad),
                None,
                "malformed {bad} must be dropped"
            );
        }
    }

    // Parsing is exercised through `parse_ice_servers`, never by rewriting the global
    // `ice-servers` option: `set_option` persists to the real config file and the tests share
    // one process, so mutating it raced every peer connection the loopback tests were building.
    #[test]
    fn test_webrtc_ice_server_list() {
        assert_eq!(
            WebRTCStream::parse_ice_servers("")[0].urls[0],
            DEFAULT_ICE_SERVERS[0].to_string()
        );

        // Unusable entries drop out of the list; the rest of the config still applies.
        let parsed = WebRTCStream::parse_ice_servers(
            ",stun://example.com,turn://u:p@example.com,turn://nocreds.example.com,sdf",
        );
        assert_eq!(parsed[0].urls[0], "stun:example.com:3478");
        assert_eq!(parsed[1].urls[0], "turn:example.com:3478");
        assert_eq!(parsed.len(), 2);

        // TURN-only config still gets the default STUN servers prepended.
        let turn_only = WebRTCStream::parse_ice_servers("turn://u:p@example.com:3478");
        assert_eq!(turn_only[0].urls[0], DEFAULT_ICE_SERVERS[0].to_string());
        assert_eq!(turn_only[1].urls[0], "turn:example.com:3478");
    }

    #[test]
    fn test_endpoint_ice_policy_declaration() {
        // An envelope with the marker declares full ICE; everything else — no marker,
        // wrong value, foreign scheme, garbage — reads as the old Relay-only semantics.
        let marked =
            WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0","ice_policy":"all"}"#);
        assert!(WebRTCStream::endpoint_declares_all_ice(&marked));

        let unmarked = WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0"}"#);
        assert!(!WebRTCStream::endpoint_declares_all_ice(&unmarked));

        let wrong =
            WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0","ice_policy":"relay"}"#);
        assert!(!WebRTCStream::endpoint_declares_all_ice(&wrong));

        assert!(!WebRTCStream::endpoint_declares_all_ice(""));
        assert!(!WebRTCStream::endpoint_declares_all_ice(
            "webrtc://not-base64!"
        ));
        assert!(!WebRTCStream::endpoint_declares_all_ice(
            "https://example.com"
        ));

        // The marker must be invisible to the plain RTCSessionDescription parse old peers do.
        let sdp_json = WebRTCStream::get_remote_offer(&marked).unwrap();
        serde_json::from_str::<
            webrtc::peer_connection::sdp::session_description::RTCSessionDescription,
        >(&sdp_json)
        .expect("extra envelope key must not break RTCSessionDescription parsing");
    }

    #[test]
    fn test_webrtc_session_key() {
        let mut sdp_str = "".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .unwrap_or_default(),
            ""
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT"
            .to_owned();
        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .is_err(),
            "can not find fingerprint attribute"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=audio 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .is_err(),
            "can not find datachannel fingerprint attribute"
        );

        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer("".to_owned()).unwrap_or_default()
            )
            .is_err(),
            "invalid sdp should error"
        );

        assert!(
            WebRTCStream::get_key_for_sdp_json("{}").is_err(),
            "empty sdp json should error"
        );

        assert!(
            WebRTCStream::get_key_for_sdp_json("{ss}").is_err(),
            "invalid sdp json should error"
        );

        let endpoint = "webrtc://eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoidj0wXHJcbm89LSA0MTA1NDk3NTY2NDgyMTQzODEwIDYwMzk1NzQw\
MCBJTiBJUDQgMC4wLjAuMFxyXG5zPS1cclxudD0wIDBcclxuYT1maW5nZXJwcmludDpzaGEtMjU2IDYxOjYwOjc0OjQwOjI4OkNFOjBCOjBDOjc1OjRCOj\
EwOjlBOkVFOjc3OkY1OjQ0OjU3Ojg0OjUxOkRCOjA0OjkyOjRBOjEwOjFDOjRFOjVGOjdFOkYxOkIzOjcxOjIyXHJcbmE9Z3JvdXA6QlVORExFIDBcclxu\
YT1leHRtYXAtYWxsb3ctbWl4ZWRcclxubT1hcHBsaWNhdGlvbiA5IFVEUC9EVExTL1NDVFAgd2VicnRjLWRhdGFjaGFubmVsXHJcbmM9SU4gSVA0IDAuMC\
4wLjBcclxuYT1zZXR1cDphY3RpdmVcclxuYT1taWQ6MFxyXG5hPXNlbmRyZWN2XHJcbmE9c2N0cC1wb3J0OjUwMDBcclxuYT1pY2UtdWZyYWc6SHlnU1Rr\
V2RsRlpHRG1XWlxyXG5hPWljZS1wd2Q6SkJneFZWaGZveVhHdHZha1VWcnBQeHVOSVpMU3llS1pcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDEgdWRwID\
IxMzA3MDY0MzEgMTkyLjE2OC4xLjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDIgdWRwIDIxMzA3MDY0MzEgMTkyLjE2OC4x\
LjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6MTg2MTA0NTE5MCAxIHVkcCAxNjk0NDk4ODE1IDE0LjIxMi42OC4xMiAyNzAwNCB0eXAgc3JmbH\
ggcmFkZHIgMC4wLjAuMCBycG9ydCA2NDAwOFxyXG5hPWNhbmRpZGF0ZToxODYxMDQ1MTkwIDIgdWRwIDE2OTQ0OTg4MTUgMTQuMjEyLjY4LjEyIDI3MDA0\
IHR5cCBzcmZseCByYWRkciAwLjAuMC4wIHJwb3J0IDY0MDA4XHJcbmE9ZW5kLW9mLWNhbmRpZGF0ZXNcclxuIn0=".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp_json(
                &WebRTCStream::get_remote_offer(&endpoint).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 61:60:74:40:28:CE:0B:0C:75:4B:10:9A:EE:77:F5:44:57:84:51:DB:04:92:4A:10:1C:4E:5F:7E:F1:B3:71:22"
        );
    }

    #[tokio::test]
    async fn test_webrtc_new_stream() {
        let mut endpoint = "webrtc://sdfsdf".to_owned();
        assert!(
            WebRTCStream::new(&endpoint, false, 10000).await.is_err(),
            "invalid webrtc endpoint should error"
        );

        endpoint = "wss://sdfsdf".to_owned();
        assert!(
            WebRTCStream::new(&endpoint, false, 10000).await.is_err(),
            "invalid webrtc endpoint should error"
        );

        assert!(
            WebRTCStream::new("", false, 10000).await.is_ok(),
            "local webrtc endpoint should ok"
        );

        endpoint = "webrtc://eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoidj0wXHJcbm89LSA0MTA1NDk3NTY2NDgyMTQzODEwIDYwMzk1NzQw\
MCBJTiBJUDQgMC4wLjAuMFxyXG5zPS1cclxudD0wIDBcclxuYT1maW5nZXJwcmludDpzaGEtMjU2IDYxOjYwOjc0OjQwOjI4OkNFOjBCOjBDOjc1OjRCOj\
EwOjlBOkVFOjc3OkY1OjQ0OjU3Ojg0OjUxOkRCOjA0OjkyOjRBOjEwOjFDOjRFOjVGOjdFOkYxOkIzOjcxOjIyXHJcbmE9Z3JvdXA6QlVORExFIDBcclxu\
YT1leHRtYXAtYWxsb3ctbWl4ZWRcclxubT1hcHBsaWNhdGlvbiA5IFVEUC9EVExTL1NDVFAgd2VicnRjLWRhdGFjaGFubmVsXHJcbmM9SU4gSVA0IDAuMC\
4wLjBcclxuYT1zZXR1cDphY3RpdmVcclxuYT1taWQ6MFxyXG5hPXNlbmRyZWN2XHJcbmE9c2N0cC1wb3J0OjUwMDBcclxuYT1pY2UtdWZyYWc6SHlnU1Rr\
V2RsRlpHRG1XWlxyXG5hPWljZS1wd2Q6SkJneFZWaGZveVhHdHZha1VWcnBQeHVOSVpMU3llS1pcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDEgdWRwID\
IxMzA3MDY0MzEgMTkyLjE2OC4xLjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDIgdWRwIDIxMzA3MDY0MzEgMTkyLjE2OC4x\
LjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6MTg2MTA0NTE5MCAxIHVkcCAxNjk0NDk4ODE1IDE0LjIxMi42OC4xMiAyNzAwNCB0eXAgc3JmbH\
ggcmFkZHIgMC4wLjAuMCBycG9ydCA2NDAwOFxyXG5hPWNhbmRpZGF0ZToxODYxMDQ1MTkwIDIgdWRwIDE2OTQ0OTg4MTUgMTQuMjEyLjY4LjEyIDI3MDA0\
IHR5cCBzcmZseCByYWRkciAwLjAuMC4wIHJwb3J0IDY0MDA4XHJcbmE9ZW5kLW9mLWNhbmRpZGF0ZXNcclxuIn0=".to_owned();
        assert!(
            WebRTCStream::new(&endpoint, false, 10000).await.is_err(),
            "connect to an 'answer' webrtc endpoint should error"
        );
    }

    #[tokio::test]
    async fn test_webrtc_wait_connected_timeout() {
        let mut stream = WebRTCStream::new("", false, 100).await.unwrap();
        let err = stream.wait_connected(10).await.unwrap_err();
        assert!(err.to_string().contains("timeout"));
    }

    async fn connect_loopback() -> (WebRTCStream, WebRTCStream) {
        let mut offerer = WebRTCStream::new("", false, 20000).await.unwrap();
        let offer = offerer.get_local_endpoint_trickle().await.unwrap();
        let answerer = WebRTCStream::new(&offer, false, 20000).await.unwrap();
        let answer = answerer.get_local_endpoint_trickle().await.unwrap();
        offerer.set_remote_endpoint(&answer).await.unwrap();

        // Bridge trickle candidates directly between the two peers, both directions.
        let mut off_ice = offerer.take_local_ice_rx().unwrap();
        let mut ans_ice = answerer.take_local_ice_rx().unwrap();
        let answerer_for_ice = answerer.clone();
        let offerer_for_ice = offerer.clone();
        tokio::spawn(async move {
            while let Some(c) = off_ice.recv().await {
                let _ = answerer_for_ice.add_remote_ice_candidate(&c).await;
            }
        });
        tokio::spawn(async move {
            while let Some(c) = ans_ice.recv().await {
                let _ = offerer_for_ice.add_remote_ice_candidate(&c).await;
            }
        });

        offerer.wait_connected(20000).await.unwrap();
        let mut answerer = answerer;
        answerer.wait_connected(20000).await.unwrap();
        (offerer, answerer)
    }

    // next()'s teardown paths must not be cancellable: every consumer polls next() inside a
    // select! against a timer, and an awaited close that loses that race strands the pc
    // (is_closed is already latched, so no later close retries) along with its SESSIONS entry,
    // which only the state handler evicts.
    //
    // The cancellation itself is not what this test pins — `close_detached` is a non-async fn,
    // so its callers have no await point to be cancelled at, and the compiler enforces that.
    // What needs proving is the other half: that work handed to the runtime still runs to
    // completion once the caller has walked away.
    #[tokio::test]
    async fn test_close_detached_completes_without_the_caller() {
        let (offerer, answerer) = connect_loopback().await;
        let key = format!("offer:{}", offerer.session_key());
        assert!(
            SESSIONS.lock().await.contains_key(&key),
            "offerer should be cached while live"
        );

        offerer.close_detached();
        drop(offerer);

        for _ in 0..200 {
            if !SESSIONS.lock().await.contains_key(&key) {
                answerer.close().await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("detached close never evicted the peer connection from SESSIONS");
    }

    // Whole messages are split out of the read buffer instead of copied, so the buffer is
    // consumed from the front and periodically re-initialized. Alternating whole and fragmented
    // messages exercises that against the accumulator path, and running well past one refill
    // exercises the refill itself — a boundary the fixed-size buffer never had.
    #[tokio::test]
    async fn test_webrtc_mixed_message_sizes_survive_scratch_refill() {
        let (mut offerer, mut answerer) = connect_loopback().await;

        // Sized either side of MAX_FRAGMENT_PAYLOAD, and enough rounds to consume several
        // SCRATCH_REFILL chunks.
        let sizes = [1usize, 64, 60_000, 60_001, 130_000, 7];
        for round in 0..40u8 {
            for &len in &sizes {
                let payload = Bytes::from(vec![round; len]);
                offerer.send_bytes(payload.clone()).await.unwrap();
                let got = timeout(Duration::from_secs(10), answerer.next())
                    .await
                    .expect("receiver starved")
                    .expect("stream ended")
                    .expect("read failed");
                assert_eq!(got.len(), len, "round {round}, len {len}");
                assert!(
                    got.iter().all(|&b| b == round),
                    "round {}, len {}: content or boundary corrupted",
                    round,
                    len
                );
            }
        }

        offerer.close().await;
        answerer.close().await;
    }

    // Owning the Stream owns the peer connection: dropping it must close the pc and evict the
    // session, without the owner having to remember to. Every exit path used to carry that
    // obligation, and the controlled side never honoured it.
    #[tokio::test]
    async fn dropping_the_stream_closes_the_peer_connection() {
        let offerer = WebRTCStream::new("", false, 20000).await.unwrap();
        let key = format!("offer:{}", offerer.session_key());
        assert!(
            SESSIONS.lock().await.contains_key(&key),
            "offerer should be cached while live"
        );

        // No explicit close anywhere: the stream simply goes out of scope, as it does on the
        // exits that forget.
        drop(crate::Stream::WebRTC(offerer));

        for _ in 0..200 {
            if !SESSIONS.lock().await.contains_key(&key) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("dropping the stream left the peer connection in SESSIONS");
    }

    // A replayed offer asking for a different ICE policy must not be handed the cached peer
    // connection. The lookup and the insert-time duplicate check read the same key, so the test
    // fails if either one stops applying `is_reusable_for` — which is how the guard was dead
    // code: the lookup rejected the entry, and the insert handed back the very same one.
    #[tokio::test]
    async fn test_cached_peer_is_not_reused_across_ice_policies() {
        let offerer = WebRTCStream::new("", false, 20000).await.unwrap();
        let offer = offerer.get_local_endpoint_trickle().await.unwrap();

        let all_ice = WebRTCStream::new(&offer, false, 20000).await.unwrap();
        assert!(!all_ice.relay_only);

        let relay_only = WebRTCStream::new(&offer, true, 20000).await.unwrap();
        assert!(
            relay_only.relay_only,
            "a Relay-only request was answered with the cached All-policy peer connection"
        );

        relay_only.close().await;
        all_ice.close().await;
        offerer.close().await;
    }

    // The local-candidate channel must close when the pc does. Its only sender lives inside the
    // on_ice_candidate handler, which close() does not clear, so without the teardown the
    // receiver stays open forever — and the forwarder loop this API asks callers to write holds
    // a stream clone while parked on recv(), keeping the pc alive past its own close.
    #[tokio::test]
    async fn test_local_ice_channel_closes_with_the_peer_connection() {
        let offerer = WebRTCStream::new("", false, 20000).await.unwrap();
        let mut ice_rx = offerer.take_local_ice_rx().unwrap();

        // Exactly the loop every consumer writes, holding a clone of the stream.
        let forwarder_stream = offerer.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(candidate) = ice_rx.recv().await {
                let _ = forwarder_stream.add_remote_ice_candidate(&candidate).await;
            }
        });

        offerer.close().await;
        drop(offerer);

        tokio::time::timeout(Duration::from_secs(20), forwarder)
            .await
            .expect("forwarder task outlived the peer connection")
            .unwrap();
    }

    // Extra channels opened after the bootstrap one must not displace it: rebinding would leave
    // teardown closing a channel send/recv no longer use, and the newcomer's on_open would push
    // Open onto the watch that gates both, re-arming a session already latched Closed.
    //
    // Scope, honestly: only the bind-once guard is exercised. The ordered+reliable check sits
    // ahead of it but cannot decide anything here — `WebRTCStream::new` always creates its
    // bootstrap channel first, so whatever the offerer adds afterwards is refused for being
    // second regardless of its parameters. Covering that check needs a hand-built peer whose
    // FIRST channel is unordered, which is more scaffolding than the guard is worth; it is a
    // three-accessor test against parameters webrtc-rs derives verbatim from the remote's DCEP.
    #[tokio::test]
    async fn test_webrtc_answerer_binds_only_the_first_data_channel() {
        use webrtc::data_channel::data_channel_init::RTCDataChannelInit;

        let mut offerer = WebRTCStream::new("", false, 20000).await.unwrap();
        // Replace the bootstrap channel's siblings: an unordered one and a duplicate.
        let unordered = offerer
            .pc
            .create_data_channel(
                "unordered",
                Some(RTCDataChannelInit {
                    ordered: Some(false),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        let duplicate = offerer
            .pc
            .create_data_channel("duplicate", None)
            .await
            .unwrap();

        let offer = offerer.get_local_endpoint_trickle().await.unwrap();
        let answerer = WebRTCStream::new(&offer, false, 20000).await.unwrap();
        let answer = answerer.get_local_endpoint_trickle().await.unwrap();
        offerer.set_remote_endpoint(&answer).await.unwrap();

        let mut off_ice = offerer.take_local_ice_rx().unwrap();
        let mut ans_ice = answerer.take_local_ice_rx().unwrap();
        let answerer_for_ice = answerer.clone();
        let offerer_for_ice = offerer.clone();
        tokio::spawn(async move {
            while let Some(c) = off_ice.recv().await {
                let _ = answerer_for_ice.add_remote_ice_candidate(&c).await;
            }
        });
        tokio::spawn(async move {
            while let Some(c) = ans_ice.recv().await {
                let _ = offerer_for_ice.add_remote_ice_candidate(&c).await;
            }
        });

        offerer.wait_connected(20000).await.unwrap();
        let mut answerer = answerer;
        answerer.wait_connected(20000).await.unwrap();

        // The bootstrap channel still carries data: the rejected siblings did not displace it.
        let payload = Bytes::from_static(b"bootstrap still bound");
        offerer.send_bytes(payload.clone()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), answerer.next())
            .await
            .expect("answerer starved")
            .expect("stream ended")
            .expect("read failed");
        assert_eq!(&got[..], &payload[..]);

        drop(unordered);
        drop(duplicate);
        offerer.close().await;
        answerer.close().await;
    }

    // One-shot callers exchange only the endpoints and never consume `take_local_ice_rx`.
    #[tokio::test]
    async fn test_webrtc_loopback_gathered_endpoints() {
        let connect = async {
            let mut offerer = WebRTCStream::new("", false, 20000).await.unwrap();
            let offer = offerer.get_local_endpoint().await.unwrap();
            let mut answerer = WebRTCStream::new(&offer, false, 20000).await.unwrap();
            let answer = answerer.get_local_endpoint().await.unwrap();
            offerer.set_remote_endpoint(&answer).await.unwrap();

            offerer.wait_connected(20000).await.unwrap();
            answerer.wait_connected(20000).await.unwrap();
            offerer.close().await;
            answerer.close().await;
        };
        timeout(Duration::from_secs(40), connect)
            .await
            .expect("gathered-endpoint WebRTC loopback did not complete in time");
    }

    // In-process offerer<->answerer loopback exercising the send/next data plane that the framing,
    // empty-message, and EOF fixes live in. Connects over host candidates (works offline; any
    // configured/default STUN just fails in the background without blocking the host pair).
    #[tokio::test]
    async fn test_webrtc_loopback_roundtrip() {
        let connect = async {
            let (mut offerer, mut answerer) = connect_loopback().await;

            // Host-candidate loopback is direct, never TURN-relayed.
            assert_eq!(offerer.is_relayed().await, Some(false));

            // Small message.
            offerer.send_raw(b"hello".to_vec()).await.unwrap();
            let got = answerer.next().await.unwrap().unwrap();
            assert_eq!(&got[..], b"hello");

            // Empty message: must round-trip as an empty frame, not be seen as EOF.
            offerer.send_raw(Vec::new()).await.unwrap();
            let got = answerer.next().await.unwrap().unwrap();
            assert_eq!(got.len(), 0, "empty message must not be treated as EOF");

            // Payload far above the 64KB single-message cap: must be fragmented and reassembled.
            let big = vec![0xABu8; 200_000];
            offerer.send_raw(big.clone()).await.unwrap();
            let got = answerer.next().await.unwrap().unwrap();
            assert_eq!(
                got.len(),
                big.len(),
                "large message must survive fragmentation"
            );
            assert_eq!(&got[..], &big[..]);

            // Reverse direction.
            answerer.send_raw(b"world".to_vec()).await.unwrap();
            let got = offerer.next().await.unwrap().unwrap();
            assert_eq!(&got[..], b"world");

            // Peer close: the other side observes a clean EOF (None) or a close error, never a hang.
            offerer.close().await;
            match timeout(Duration::from_secs(10), answerer.next()).await {
                Ok(None) | Ok(Some(Err(_))) => {}
                Ok(Some(Ok(b))) => panic!("expected EOF after peer close, got {} bytes", b.len()),
                Err(_) => panic!("answerer.next() hung after peer close"),
            }
            answerer.close().await;
        };
        timeout(Duration::from_secs(40), connect)
            .await
            .expect("webrtc loopback did not complete in time");
    }

    // Both framing violations must end the stream. The empty-FRAG_MORE case is the one that
    // cannot be caught downstream: it adds nothing to the accumulator, so the MAX_FRAME_LENGTH
    // cap never trips and `next()` would otherwise spin for as long as the peer keeps writing.
    // The bad frame is injected mid-message so the branch's `acc` reset is exercised too.
    #[tokio::test]
    async fn test_webrtc_rejects_bad_fragment_framing() {
        // (raw frame, expected substring)
        let cases: [(&[u8], &str); 2] = [
            (&[0x2A, b'x'], "fragment header 42"),
            (&[FRAG_MORE], "carries no payload"),
        ];
        for (frame, want) in cases {
            let connect = async {
                let (offerer, mut answerer) = connect_loopback().await;
                let dc = offerer.detached_dc().await.unwrap();

                // Leave a partial message in the accumulator first, so the rejection has
                // something to discard. `send_bytes` only ever emits valid headers, so the bad
                // frame itself has to be written through the raw channel below it.
                let mut lead = BytesMut::with_capacity(1 + 8);
                lead.put_u8(FRAG_MORE);
                lead.put_slice(b"leading!");
                dc.write(&lead.freeze()).await.unwrap();
                dc.write(&bytes::Bytes::copy_from_slice(frame))
                    .await
                    .unwrap();

                let err = answerer
                    .next()
                    .await
                    .expect("bad framing must surface as an error, not EOF")
                    .expect_err("bad framing must be rejected");
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
                assert!(err.to_string().contains(want), "unexpected error: {}", err);

                offerer.close().await;
                answerer.close().await;
            };
            timeout(Duration::from_secs(40), connect)
                .await
                .expect("webrtc loopback did not complete in time");
        }
    }

    #[tokio::test]
    async fn test_webrtc_concurrent_large_sends_preserve_boundaries() {
        let connect = async {
            let (offerer, mut answerer) = connect_loopback().await;
            let mut sender_a = offerer.clone();
            let mut sender_b = offerer.clone();
            let expected_a = vec![0xAA; 200_000];
            let expected_b = vec![0xBB; 200_000];
            let payload_a = expected_a.clone();
            let payload_b = expected_b.clone();
            let barrier = Arc::new(Barrier::new(3));

            let barrier_a = barrier.clone();
            let send_a = tokio::spawn(async move {
                barrier_a.wait().await;
                sender_a.send_raw(payload_a).await
            });
            let barrier_b = barrier.clone();
            let send_b = tokio::spawn(async move {
                barrier_b.wait().await;
                sender_b.send_raw(payload_b).await
            });

            barrier.wait().await;
            let receive = async {
                let first = answerer.next().await.unwrap().unwrap();
                let second = answerer.next().await.unwrap().unwrap();
                (first, second)
            };
            let (send_a, send_b, (first, second)) = tokio::join!(send_a, send_b, receive);
            send_a.unwrap().unwrap();
            send_b.unwrap().unwrap();

            let boundaries_preserved = (first.as_ref() == expected_a.as_slice()
                && second.as_ref() == expected_b.as_slice())
                || (first.as_ref() == expected_b.as_slice()
                    && second.as_ref() == expected_a.as_slice());
            assert!(boundaries_preserved, "concurrent messages were interleaved");

            offerer.close().await;
            answerer.close().await;
        };
        timeout(Duration::from_secs(40), connect)
            .await
            .expect("concurrent WebRTC sends did not complete in time");
    }
}
