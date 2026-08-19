//! socket binding over loopback, so no root needed. proves the source ip is
//! applied to the socket, that an unusable value falls back instead of cutting
//! the connection, and that the websocket transport is bound too.

use hbb_common::{
    config::{keys, Config},
    socket_client, tcp,
};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::Duration;

// Config is global process state; serialize and restore so we never leave the
// host's real config modified.
static LOCK: Mutex<()> = Mutex::new(());

// A panicking test poisons the mutex; without recovery every later test then
// fails on the lock instead of running, hiding which one actually broke.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct BindRestore(String);

impl BindRestore {
    fn save() -> Self {
        Self(Config::get_option(keys::OPTION_BIND_INTERFACE))
    }
}

impl Drop for BindRestore {
    fn drop(&mut self) {
        set_bind(&self.0);
    }
}

fn set_bind(interface: &str) {
    Config::set_option(keys::OPTION_BIND_INTERFACE.to_owned(), interface.to_owned());
}

#[tokio::test]
async fn bind_source_ip_end_to_end() {
    let _guard = lock();
    let _restore = BindRestore::save();

    // A present local address (loopback always exists) is selected.
    set_bind("127.0.0.1");
    assert_eq!(
        Config::get_bind_source_ip(true).map(|ip| ip.to_string()),
        Some("127.0.0.1".to_owned())
    );

    // Anything unusable falls back to letting the OS choose.
    set_bind("203.0.113.7");
    assert_eq!(Config::get_bind_source_ip(true), None);
    set_bind("definitely-not-an-interface");
    assert_eq!(Config::get_bind_source_ip(true), None);
    // ... and then must not pin a device either, or the socket would fail
    assert_eq!(Config::get_bind_device(true), None);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = format!("127.0.0.1:{port}");

    // Bound to a present local IP: connects, and the socket carries it.
    set_bind("127.0.0.1");
    // connect_tcp_local, not connect_tcp: the latter diverts to the websocket
    // path when allow-websocket is set in the host config, which would test
    // nothing about socket binding and make the result depend on the machine.
    let stream = socket_client::connect_tcp_local(target.clone(), None, 3000)
        .await
        .expect("bind to present local IP should connect");
    assert_eq!(
        stream.local_addr().ip().to_string(),
        "127.0.0.1",
        "outgoing socket must be bound to the configured source IP"
    );
    drop(stream);

    // Unusable values fall back and still connect -- never fail closed.
    for v in ["203.0.113.7", "definitely-not-an-interface", ""] {
        set_bind(v);
        socket_client::connect_tcp_local(target.clone(), None, 3000)
            .await
            .unwrap_or_else(|e| panic!("bind-interface {v:?} should fall back and connect: {e}"));
    }
}

// The websocket transport used to dial via tungstenite's own connect_async,
// which opens an unbound socket -- so with allow-websocket set, the binding did
// not apply to outgoing connections at all. Over loopback we can only show it
// still connects: with strict gone, an address that is not enumerated falls
// back, so there is no way to force a distinguishable source here. The source
// address is proven against real interfaces in the network-namespace run.
#[tokio::test]
async fn websocket_transport_still_connects_when_bound() {
    let _guard = lock();
    let _restore = BindRestore::save();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    set_bind("127.0.0.1");
    let url = format!("ws://127.0.0.1:{port}");
    let dial = tokio::spawn(async move {
        let _ = hbb_common::websocket::WsFramedStream::new(url, None, None, 3000).await;
    });

    let (_sock, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("websocket dial did not connect in time")
        .expect("accept failed");
    assert_eq!(peer.ip().to_string(), "127.0.0.1");
    dial.abort();
}

// new_listener() binds caller-supplied addresses; the port-forward and RDP
// listeners use 127.0.0.1. Pinning those to a configured interface would filter
// out traffic arriving on loopback and make them unreachable.
#[tokio::test]
async fn explicit_listeners_are_not_pinned() {
    let _guard = lock();
    let _restore = BindRestore::save();

    set_bind("127.0.0.2");
    let l = tcp::new_listener("127.0.0.1:0", true)
        .await
        .expect("explicit loopback listener must still bind");
    let port = l.local_addr().unwrap().port();

    set_bind("");
    let s = socket_client::connect_tcp_local(format!("127.0.0.1:{port}"), None, 3000).await;
    assert!(s.is_ok(), "explicit loopback listener must stay reachable");
}

#[tokio::test]
async fn listener_falls_back_instead_of_failing() {
    let _guard = lock();
    let _restore = BindRestore::save();

    set_bind("");
    let l = tcp::listen_any(0).await.expect("default should listen");
    assert!(
        l.local_addr().unwrap().ip().is_unspecified(),
        "unbound listener must stay on the wildcard address"
    );
    drop(l);

    set_bind("127.0.0.1");
    let l = tcp::listen_any(0).await.expect("present address should listen");
    assert_eq!(l.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    drop(l);

    // unusable: listen on all interfaces rather than refusing, and in
    // particular not on loopback -- that would be "listening" while
    // unreachable, which is the regression this whole path exists to avoid
    set_bind("definitely-not-an-interface");
    let l = tcp::listen_any(0)
        .await
        .expect("an unusable binding must fall back to all interfaces");
    assert!(
        l.local_addr().unwrap().ip().is_unspecified(),
        "fallback listener must bind the wildcard address, not loopback"
    );
}
