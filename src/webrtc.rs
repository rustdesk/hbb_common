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
//! - **Stats-based `is_relayed()`**: `RTCIceCandidatePair`'s candidates are private in 0.13;
//!   0.17+ makes them `pub`, allowing direct field access instead of the stats scan.
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
use webrtc::stats::StatsReportType;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::time::{timeout, timeout_at, Instant};
use url::Url;

use crate::bytes_codec::MAX_FRAME_LENGTH;
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
    // Receive-side reassembly state. The accumulator survives a cancelled `next()` because it
    // lives here behind the Arc, not in the future. The mutex excludes a concurrent reader only
    // while `next()` is actually running — a cancellation drops the guard mid-message, so it is
    // the single-reader assumption, not the lock, that ultimately prevents two readers splicing
    // into one `acc`. Single reader assumed, like the rest of the stream API.
    recv_state: Arc<Mutex<RecvState>>,
    // True once the controller has completed the RustDesk identity binding (DTLS fingerprint
    // matched to the signed peer id, via `set_key`). DTLS always encrypts; this flag mirrors TCP's
    // "secured after key exchange" so key-less / unbound WebRTC is not shown as peer-authenticated.
    peer_verified: Arc<AtomicBool>,
}

#[derive(Default)]
struct RecvState {
    // Accumulated payload of the logical message currently being reassembled.
    acc: BytesMut,
    // Reused read scratch buffer, avoiding a per-message allocation.
    scratch: Vec<u8>,
}

// The SCTP data channel's 65536-byte max message size is handled by
// splitting a logical message into fragments carrying a 1-byte header. Fragment payload is kept
// well under the limit so header+payload never reaches the exact-65536 boundary that the
// receiver's reassembly would truncate with data loss.
const MAX_FRAGMENT_PAYLOAD: usize = 60000;
/// Receive scratch size: must be >= 1 (fragment header) + `MAX_FRAGMENT_PAYLOAD` and fit the
/// negotiated SCTP max message size.
const RECV_BUF_SIZE: usize = 64 * 1024;
/// Fragment header byte: more fragments follow for this logical message.
const FRAG_MORE: u8 = 1;
/// Fragment header byte: final (or only) fragment of a logical message.
const FRAG_END: u8 = 0;
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
    const ICE_POLICY_KEY: &str = "ice_policy";
    const ICE_POLICY_ALL: &str = "all";

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
        // standard url format with turn scheme: turn://user:pass@host:port
        match Url::parse(url) {
            Ok(u) => {
                if u.scheme() == "turn"
                    || u.scheme() == "turns"
                    || u.scheme() == "stun"
                    || u.scheme() == "stuns"
                {
                    Some(RTCIceServer {
                        urls: vec![format!(
                            "{}:{}:{}",
                            u.scheme(),
                            u.host_str().unwrap_or_default(),
                            u.port().unwrap_or(3478)
                        )],
                        username: u.username().to_string(),
                        credential: u.password().unwrap_or_default().to_string(),
                        ..Default::default()
                    })
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Whether the ICE configuration contains a usable TURN server. A Relay-policy peer
    /// connection (force_relay) can only gather relay candidates, so without a TURN server it can
    /// never connect — callers use this to skip building a guaranteed-dead pc.
    pub fn has_turn_server() -> bool {
        Self::get_ice_servers().iter().any(|s| {
            s.urls
                .iter()
                .any(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        })
    }

    #[inline]
    fn get_ice_servers() -> Vec<RTCIceServer> {
        let mut ice_servers = Vec::new();
        let cfg = config::Config::get_option(config::keys::OPTION_ICE_SERVERS);

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
            let sessions_lock = SESSIONS.lock().await;
            if let Some(cached_stream) =
                sessions_lock.get(&Self::cache_key(&key, start_local_offer))
            {
                log::debug!("Start webrtc with cached peer");
                return Ok(cached_stream.clone());
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
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let d_label = dc.label().to_owned();
                let dc_open_notify2 = dc_open_notify.clone();
                let stream_for_dc_clone = stream_for_dc.clone();
                log::debug!("Remote data channel {} ready", d_label);
                Box::pin(async move {
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
                        let _ = on_connection_notify.send(WebRTCConnectionState::Closed(
                            s.to_string(),
                        ));
                        log::debug!("WebRTC session closing due to {}", s);
                        let _ = stream_for_close2.lock().await.close().await;
                        log::debug!("WebRTC session stream closed");

                        let Some(pc_for_close2) = pc_for_close2.upgrade() else {
                            return;
                        };
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
            if let Some(session) = final_lock.get(&cache_key) {
                Some(session.clone())
            } else {
                final_lock.insert(cache_key, webrtc_stream.clone());
                None
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
        dtls.ice_transport().get_selected_candidate_pair().await?;

        // webrtc 0.13 keeps RTCIceCandidatePair's candidates private. Its stats report exposes
        // the selected (nominated) pair and the corresponding candidate types instead.
        let stats = self.pc.get_stats().await;
        let pair = stats.reports.values().find_map(|report| match report {
            StatsReportType::CandidatePair(pair) if pair.nominated => Some(pair),
            _ => None,
        })?;
        let is_relay = |candidate_id: &str| {
            matches!(
                stats.reports.get(candidate_id),
                Some(
                    StatsReportType::LocalCandidate(candidate)
                        | StatsReportType::RemoteCandidate(candidate)
                ) if RTCIceCandidateType::from(candidate.candidate_type)
                    == RTCIceCandidateType::Relay
            )
        };
        Some(
            is_relay(&pair.local_candidate_id) || is_relay(&pair.remote_candidate_id),
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
            let deadline = Instant::now() + Duration::from_millis(send_timeout);
            let _send_permit = match timeout_at(deadline, send_gate.acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(err)) => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        format!("WebRTC send gate closed: {}", err),
                    )
                    .into());
                }
                Err(_) => {
                    if let Err(err) = self.pc.close().await {
                        log::warn!("failed to close WebRTC after send timeout: {}", err);
                    }
                    return Err(Error::new(ErrorKind::TimedOut, "WebRTC send timeout").into());
                }
            };
            match timeout_at(deadline, self.send_bytes_inner(bytes)).await {
                Ok(res) => res,
                Err(_) => {
                    // Keep the logical-message permit while closing so no waiting clone can append
                    // a new message after a partially-written fragment sequence.
                    if let Err(err) = self.pc.close().await {
                        log::warn!("failed to close WebRTC after send timeout: {}", err);
                    }
                    Err(Error::new(ErrorKind::TimedOut, "WebRTC send timeout").into())
                }
            }
        } else {
            let _send_permit = send_gate.acquire_owned().await.map_err(|err| {
                Error::new(
                    ErrorKind::BrokenPipe,
                    format!("WebRTC send gate closed: {}", err),
                )
            })?;
            self.send_bytes_inner(bytes).await
        }
    }

    async fn send_bytes_inner(&mut self, bytes: Bytes) -> ResultType<()> {
        if bytes.len() > MAX_FRAME_LENGTH {
            return Err(Error::new(ErrorKind::InvalidInput, "Overflow").into());
        }
        self.wait_for_connect_result().await?;
        let dc = self.detached_dc().await?;
        let data = bytes.as_ref();
        let mut offset = 0;
        // Always emit at least one fragment (a lone FRAG_END header for an empty message), so a
        // zero-length data-channel message — which the receiver cannot distinguish from EOF — is
        // never sent.
        loop {
            let end = (offset + MAX_FRAGMENT_PAYLOAD).min(data.len());
            let is_last = end >= data.len();
            let chunk = &data[offset..end];
            let mut framed = BytesMut::with_capacity(1 + chunk.len());
            framed.put_u8(if is_last { FRAG_END } else { FRAG_MORE });
            framed.put_slice(chunk);
            dc.write(&framed.freeze()).await?;
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
            self.pc.close().await.ok();
            return Some(Err(Error::new(ErrorKind::Other, err.to_string())));
        }
        let dc = match self.detached_dc().await {
            Ok(dc) => dc,
            Err(err) => {
                self.pc.close().await.ok();
                return Some(Err(Error::new(ErrorKind::Other, err.to_string())));
            }
        };
        // Held across the whole loop for exclusion, not for accumulator survival (see the field).
        // Cancelling mid-`dc.read()` loses no data; cancelling mid-`pc.close()` on an error path
        // below does leak the pc — see the checklist entry on cancel-safety.
        let mut st = self.recv_state.lock().await;
        if st.scratch.len() < RECV_BUF_SIZE {
            st.scratch.resize(RECV_BUF_SIZE, 0);
        }
        loop {
            let RecvState { acc, scratch } = &mut *st;
            let n = match dc.read(scratch.as_mut_slice()).await {
                Ok(n) => n,
                Err(err) => {
                    self.pc.close().await.ok();
                    return Some(Err(Error::new(
                        ErrorKind::Other,
                        format!("data channel read error: {}", err),
                    )));
                }
            };
            if n == 0 {
                // Clean EOF: the remote reset the stream or shut its write half. An empty logical
                // message is represented by a 1-byte header, so it is never confused with EOF.
                self.pc.close().await.ok();
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
                other => Some(format!("fragment header {other} is neither FRAG_END nor FRAG_MORE")),
            };
            if let Some(why) = bad {
                *acc = BytesMut::new();
                self.pc.close().await.ok();
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("WebRTC {why}"),
                )));
            }
            acc.extend_from_slice(&scratch[1..n]);
            // Match TCP's maximum frame size while preventing an unbounded FRAG_MORE stream from
            // exhausting memory.
            if acc.len() > MAX_FRAME_LENGTH {
                // Release the buffer, don't just truncate it: by definition it is at the cap here,
                // and `recv_state` outlives this call through the `SESSIONS` clone.
                *acc = BytesMut::new();
                self.pc.close().await.ok();
                return Some(Err(Error::new(
                    ErrorKind::InvalidData,
                    "WebRTC reassembled message exceeded maximum frame size",
                )));
            }
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
    use crate::config;
    use crate::webrtc::WebRTCStream;
    use crate::webrtc::{DEFAULT_ICE_SERVERS, FRAG_MORE};
    use bytes::{BufMut, BytesMut};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Barrier;
    use tokio::time::timeout;
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

    #[test]
    fn test_webrtc_ice_url() {
        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://example.com:3478")
                .unwrap_or_default()
                .urls[0],
            "turn:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://example.com")
                .unwrap_or_default()
                .urls[0],
            "turn:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123@example.com")
                .unwrap_or_default()
                .username,
            "123"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123@example.com")
                .unwrap_or_default()
                .credential,
            ""
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123:321@example.com")
                .unwrap_or_default()
                .credential,
            "321"
        );

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

        config::Config::set_option("ice-servers".to_string(), "".to_string());
        assert_eq!(
            WebRTCStream::get_ice_servers()[0].urls[0],
            DEFAULT_ICE_SERVERS[0].to_string()
        );

        config::Config::set_option(
            "ice-servers".to_string(),
            ",stun://example.com,turn://example.com,sdf".to_string(),
        );
        assert_eq!(
            WebRTCStream::get_ice_servers()[0].urls[0],
            "stun:example.com:3478"
        );
        assert_eq!(
            WebRTCStream::get_ice_servers()[1].urls[0],
            "turn:example.com:3478"
        );
        assert_eq!(WebRTCStream::get_ice_servers().len(), 2);
        config::Config::set_option(
            "ice-servers".to_string(),
            "".to_string(),
        );
    }

    #[test]
    fn test_endpoint_ice_policy_declaration() {
        // An envelope with the marker declares full ICE; everything else — no marker,
        // wrong value, foreign scheme, garbage — reads as the old Relay-only semantics.
        let marked = WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0","ice_policy":"all"}"#);
        assert!(WebRTCStream::endpoint_declares_all_ice(&marked));

        let unmarked = WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0"}"#);
        assert!(!WebRTCStream::endpoint_declares_all_ice(&unmarked));

        let wrong = WebRTCStream::sdp_to_endpoint(r#"{"type":"offer","sdp":"v=0","ice_policy":"relay"}"#);
        assert!(!WebRTCStream::endpoint_declares_all_ice(&wrong));

        assert!(!WebRTCStream::endpoint_declares_all_ice(""));
        assert!(!WebRTCStream::endpoint_declares_all_ice("webrtc://not-base64!"));
        assert!(!WebRTCStream::endpoint_declares_all_ice("https://example.com"));

        // The marker must be invisible to the plain RTCSessionDescription parse old peers do.
        let sdp_json = WebRTCStream::get_remote_offer(&marked).unwrap();
        serde_json::from_str::<webrtc::peer_connection::sdp::session_description::RTCSessionDescription>(&sdp_json)
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
            assert_eq!(got.len(), big.len(), "large message must survive fragmentation");
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
                dc.write(&bytes::Bytes::copy_from_slice(frame)).await.unwrap();

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
