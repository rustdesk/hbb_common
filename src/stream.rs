use crate::{config, tcp, websocket, ResultType};
#[cfg(feature = "webrtc")]
use crate::webrtc;
use sodiumoxide::crypto::secretbox::Key;
use std::net::SocketAddr;
use tokio::net::TcpStream;

// support Websocket and tcp.
pub enum Stream {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsFramedStream),
    Tcp(tcp::FramedStream),
}

impl Stream {
    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_send_timeout(ms),
            Stream::WebSocket(s) => s.set_send_timeout(ms),
            Stream::Tcp(s) => s.set_send_timeout(ms),
        }
    }

    #[inline]
    pub fn set_raw(&mut self) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_raw(),
            Stream::WebSocket(s) => s.set_raw(),
            Stream::Tcp(s) => s.set_raw(),
        }
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_bytes(bytes).await,
            Stream::WebSocket(s) => s.send_bytes(bytes).await,
            Stream::Tcp(s) => s.send_bytes(bytes).await,
        }
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_raw(bytes).await,
            Stream::WebSocket(s) => s.send_raw(bytes).await,
            Stream::Tcp(s) => s.send_raw(bytes).await,
        }
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_key(key),
            Stream::WebSocket(s) => s.set_key(key),
            Stream::Tcp(s) => s.set_key(key),
        }
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_secured(),
            Stream::WebSocket(s) => s.is_secured(),
            Stream::Tcp(s) => s.is_secured(),
        }
    }

    /// Whether this is a WebRTC transport. Used to enforce the WebRTC-only DTLS fingerprint
    /// binding (fail closed) in the secure handshake.
    #[inline]
    pub fn is_webrtc(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Close the underlying WebRTC peer connection if this is a WebRTC stream; no-op otherwise.
    /// A WebRTC pc is kept alive by the global session cache and its cleanup handler only fires on
    /// a terminal ICE state, so it must be closed explicitly at session end. TCP/WebSocket streams
    /// release their resources on drop and need nothing here.
    #[inline]
    pub async fn close_webrtc(&self) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.close().await,
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    /// Whether an established WebRTC transport runs through a TURN relay (used for the UI's
    /// direct/relayed flag). None for non-WebRTC transports or before ICE selects a pair.
    #[inline]
    pub async fn webrtc_relayed(&self) -> Option<bool> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_relayed().await,
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// DTLS certificate fingerprint for a WebRTC stream (`local`=true for this endpoint's own
    /// cert, false for the peer's), used to bind the channel to the signed peer identity.
    /// Returns None for non-WebRTC transports, which authenticate via the secretbox key exchange.
    #[inline]
    #[cfg_attr(not(feature = "webrtc"), allow(unused_variables))]
    pub async fn dtls_fingerprint(&self, local: bool) -> Option<String> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => {
                if local {
                    s.local_dtls_fingerprint().await.ok()
                } else {
                    s.remote_dtls_fingerprint().await.ok()
                }
            }
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        timeout: u64,
    ) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.next_timeout(timeout).await,
            Stream::WebSocket(s) => s.next_timeout(timeout).await,
            Stream::Tcp(s) => s.next_timeout(timeout).await,
        }
    }

    /// establish connect from websocket
    #[inline]
    pub async fn connect_websocket(
        url: impl AsRef<str>,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&config::Socks5Server>,
        timeout_ms: u64,
    ) -> ResultType<Self> {
        let ws_stream =
            websocket::WsFramedStream::new(url, local_addr, proxy_conf, timeout_ms).await?;
        log::debug!("WebSocket connection established");
        Ok(Self::WebSocket(ws_stream))
    }

    /// send message
    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.send(msg).await,
            Self::WebSocket(ws) => ws.send(msg).await,
            Self::Tcp(tcp) => tcp.send(msg).await,
        }
    }

    /// receive message
    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.next().await,
            Self::WebSocket(ws) => ws.next().await,
            Self::Tcp(tcp) => tcp.next().await,
        }
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.local_addr(),
            Self::WebSocket(ws) => ws.local_addr(),
            Self::Tcp(tcp) => tcp.local_addr(),
        }
    }

    #[inline]
    pub fn from(stream: TcpStream, stream_addr: SocketAddr) -> Self {
        Self::Tcp(tcp::FramedStream::from(stream, stream_addr))
    }

    #[inline]
    #[cfg(feature = "webrtc")]
    pub fn get_webrtc_stream(&self) -> Option<webrtc::WebRTCStream> {
        match self {
            Self::WebRTC(s) => Some(s.clone()),
            _ => None,
        }
    }
}
