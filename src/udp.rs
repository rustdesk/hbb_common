use crate::ResultType;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio_socks::{udp::Socks5UdpFramed, IntoTargetAddr, TargetAddr, ToProxyAddrs};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};

pub enum FramedSocket {
    Direct(UdpFramed<BytesCodec>),
    ProxySocks(Socks5UdpFramed),
}

#[cfg(test)]
mod send_recovery_tests {
    use super::*;
    use crate::rendezvous_proto::{RegisterPeerResponse, RendezvousMessage};

    /// Checks typed and raw UDP recovery after an incompatible destination.
    #[tokio::test]
    async fn failed_datagram_does_not_block_the_next_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sender = FramedSocket::new("127.0.0.1:0").await.unwrap();
        let original_address = sender.local_addr();
        let mut response = RendezvousMessage::new();
        response.set_register_peer_response(RegisterPeerResponse {
            request_pk: true,
            ..Default::default()
        });
        let invalid_destination: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(sender.send(&response, invalid_destination).await.is_err());
        sender.send(&response, receiver.local_addr().unwrap()).await.unwrap();
        let mut bytes = [0; 64];
        let (length, source) = crate::timeout(1000, receiver.recv_from(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(&bytes[..length], response.write_to_bytes().unwrap());
        assert_eq!(Some(source), original_address);
        assert!(sender.send_raw(b"bad destination", invalid_destination).await.is_err());
        sender.send_raw(b"next datagram", receiver.local_addr().unwrap()).await.unwrap();
        let (length, source) = crate::timeout(1000, receiver.recv_from(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(&bytes[..length], b"next datagram");
        assert_eq!(Some(source), original_address);
    }
}

/// Creates and binds a nonblocking UDP socket with optional reuse and receive buffering.
fn new_socket(addr: SocketAddr, reuse: bool, buf_size: usize) -> Result<Socket, std::io::Error> {
    let socket = match addr {
        SocketAddr::V4(..) => Socket::new(Domain::ipv4(), Type::dgram(), None),
        SocketAddr::V6(..) => Socket::new(Domain::ipv6(), Type::dgram(), None),
    }?;
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuse_port(true).ok();
        socket.set_reuse_address(true).ok();
    }
    // only nonblocking work with tokio, https://stackoverflow.com/questions/64649405/receiver-on-tokiompscchannel-only-receives-messages-when-buffer-is-full
    socket.set_nonblocking(true)?;
    if buf_size > 0 {
        socket.set_recv_buffer_size(buf_size).ok();
    }
    log::debug!(
        "Receive buf size of udp {}: {:?}",
        addr,
        socket.recv_buffer_size()
    );
    if addr.is_ipv6() && addr.ip().is_unspecified() && addr.port() > 0 {
        socket.set_only_v6(false).ok();
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

impl FramedSocket {
    pub async fn new<T: ToSocketAddrs>(addr: T) -> ResultType<Self> {
        Self::new_reuse(addr, false, 0).await
    }

    pub async fn new_reuse<T: ToSocketAddrs>(
        addr: T,
        reuse: bool,
        buf_size: usize,
    ) -> ResultType<Self> {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        Ok(Self::Direct(UdpFramed::new(
            UdpSocket::from_std(new_socket(addr, reuse, buf_size)?.into_udp_socket())?,
            BytesCodec::new(),
        )))
    }

    pub async fn new_proxy<'a, 't, P: ToProxyAddrs, T: ToSocketAddrs>(
        proxy: P,
        local: T,
        username: &'a str,
        password: &'a str,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let framed = if username.trim().is_empty() {
            super::timeout(ms_timeout, Socks5UdpFramed::connect(proxy, Some(local))).await??
        } else {
            super::timeout(
                ms_timeout,
                Socks5UdpFramed::connect_with_password(proxy, Some(local), username, password),
            )
            .await??
        };
        log::trace!(
            "Socks5 udp connected, local addr: {:?}, target addr: {}",
            framed.local_addr(),
            framed.socks_addr()
        );
        Ok(Self::ProxySocks(framed))
    }

    /// Sends a serialized message through the selected UDP transport.
    #[inline]
    pub async fn send(
        &mut self,
        msg: &impl Message,
        addr: impl IntoTargetAddr<'_>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();
        let send_data = Bytes::from(msg.write_to_bytes()?);
        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.get_ref().send_to(&send_data, addr).await?;
                }
            }
            Self::ProxySocks(f) => f.send((send_data, addr)).await?,
        };
        Ok(())
    }

    // https://stackoverflow.com/a/68733302/1926020
    /// Sends raw bytes through the selected relay or UDP transport.
    #[inline]
    pub async fn send_raw(
        &mut self,
        msg: &'static [u8],
        addr: impl IntoTargetAddr<'static>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();

        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.get_ref().send_to(msg, addr).await?;
                }
            }
            Self::ProxySocks(f) => f.send((Bytes::from(msg), addr)).await?,
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        match self {
            Self::Direct(f) => match f.next().await {
                Some(Ok((data, addr))) => {
                    Some(Ok((data, addr.into_target_addr().ok()?.to_owned())))
                }
                Some(Err(e)) => Some(Err(anyhow!(e))),
                None => None,
            },
            Self::ProxySocks(f) => match f.next().await {
                Some(Ok((data, _))) => Some(Ok((data.data, data.dst_addr))),
                Some(Err(e)) => Some(Err(anyhow!(e))),
                None => None,
            },
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        ms: u64,
    ) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        if let Ok(res) =
            tokio::time::timeout(std::time::Duration::from_millis(ms), self.next()).await
        {
            res
        } else {
            None
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        if let FramedSocket::Direct(x) = self {
            if let Ok(v) = x.get_ref().local_addr() {
                return Some(v);
            }
        }
        None
    }
}
