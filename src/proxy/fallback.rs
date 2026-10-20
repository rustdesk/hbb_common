use crate::{
    bail,
    config::{keys::OPTION_ALLOW_PROXY_FALLBACK, Config, Socks5Server},
    proxy::IntoUrl,
    ResultType,
};
use anyhow::Context;
use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    time::{Duration, Instant},
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_DURATION: Duration = Duration::from_secs(5);

struct Availability {
    proxy: String,
    reachable: bool,
    checked_at: Instant,
}

static AVAILABILITY: Mutex<Option<Availability>> = Mutex::new(None);

pub fn is_fallback_enabled() -> bool {
    Config::get_option(OPTION_ALLOW_PROXY_FALLBACK) == "Y"
}

fn endpoint(proxy: &str) -> ResultType<(String, u16)> {
    let url = if proxy.contains("://") {
        proxy.into_url()?
    } else {
        format!("socks5://{proxy}").into_url()?
    };
    let default_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        "socks5" => 1080,
        _ => bail!("Unsupported proxy scheme"),
    };
    let host = url.host_str().context("Missing proxy host")?;
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        url.port().unwrap_or(default_port),
    ))
}

fn cached_availability(proxy: &str) -> Option<bool> {
    AVAILABILITY.lock().unwrap().as_ref().and_then(|cached| {
        (!cached.reachable && cached.proxy == proxy && cached.checked_at.elapsed() < CACHE_DURATION)
            .then_some(cached.reachable)
    })
}

fn remember_availability(proxy: &str, reachable: bool) {
    if !reachable {
        log::info!("Configured proxy is unreachable, trying a direct connection");
    }
    *AVAILABILITY.lock().unwrap() = Some(Availability {
        proxy: proxy.to_owned(),
        reachable,
        checked_at: Instant::now(),
    });
}

// Probe only the proxy's TCP endpoint. Authentication, TLS and target errors
// must not cause the client to bypass a reachable proxy.
pub async fn get_socks() -> Option<Socks5Server> {
    let conf = Config::get_socks()?;
    if !is_fallback_enabled() {
        return Some(conf);
    }
    let reachable = if let Some(reachable) = cached_availability(&conf.proxy) {
        reachable
    } else {
        let addr = match endpoint(&conf.proxy) {
            Ok(addr) => addr,
            Err(_) => return Some(conf),
        };
        let reachable = matches!(
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
            Ok(Ok(_))
        );
        remember_availability(&conf.proxy, reachable);
        reachable
    };
    reachable.then_some(conf)
}

pub fn get_socks_sync() -> Option<Socks5Server> {
    let conf = Config::get_socks()?;
    if !is_fallback_enabled() {
        return Some(conf);
    }
    let reachable = if let Some(reachable) = cached_availability(&conf.proxy) {
        reachable
    } else {
        let addr = match endpoint(&conf.proxy) {
            Ok(addr) => addr,
            Err(_) => return Some(conf),
        };
        let started = Instant::now();
        let reachable = addr.to_socket_addrs().map_or(false, |mut addrs| {
            addrs.any(|addr| {
                let remaining = PROBE_TIMEOUT.saturating_sub(started.elapsed());
                !remaining.is_zero() && TcpStream::connect_timeout(&addr, remaining).is_ok()
            })
        });
        remember_availability(&conf.proxy, reachable);
        reachable
    };
    reachable.then_some(conf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{keys::OPTION_PROXY_URL, OVERWRITE_SETTINGS},
        socket_client::connect_tcp,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpSocket},
        time::timeout,
    };

    struct RestoreSettings(Vec<(&'static str, Option<String>)>);

    impl Drop for RestoreSettings {
        fn drop(&mut self) {
            let mut settings = OVERWRITE_SETTINGS.write().unwrap();
            for (key, value) in self.0.drain(..) {
                if let Some(value) = value {
                    settings.insert(key.to_owned(), value);
                } else {
                    settings.remove(key);
                }
            }
            *AVAILABILITY.lock().unwrap() = None;
        }
    }

    fn set_option(key: &str, value: &str) {
        OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
    }

    #[test]
    fn proxy_endpoints() {
        for (proxy, host, port) in [
            ("office:1080", "office", 1080),
            ("socks5://office", "office", 1080),
            ("http://user:password@office", "office", 80),
            ("https://office:8443", "office", 8443),
            ("http://[::1]:8080", "::1", 8080),
            ("[::1]:1080", "::1", 1080),
        ] {
            assert_eq!(endpoint(proxy).unwrap(), (host.to_owned(), port));
        }
        assert!(endpoint("ftp://office").is_err());
        assert!(endpoint("http://").is_err());
    }

    #[tokio::test]
    async fn proxy_fallback_is_opt_in_and_recovers() {
        let _restore = RestoreSettings(
            [OPTION_PROXY_URL, OPTION_ALLOW_PROXY_FALLBACK]
                .iter()
                .copied()
                .map(|key| (key, OVERWRITE_SETTINGS.read().unwrap().get(key).cloned()))
                .collect(),
        );
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let proxy_socket = TcpSocket::new_v4().unwrap();
        proxy_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let proxy_addr = proxy_socket.local_addr().unwrap();
        let http_proxy = format!("http://{proxy_addr}");
        set_option(OPTION_PROXY_URL, &http_proxy);

        for disabled in ["", "N"] {
            set_option(OPTION_ALLOW_PROXY_FALLBACK, disabled);
            assert_eq!(get_socks().await, Config::get_socks());
            assert_eq!(get_socks_sync(), Config::get_socks());
            assert!(connect_tcp(target_addr, 300).await.is_err());
            assert!(timeout(Duration::from_millis(20), target.accept())
                .await
                .is_err());
        }

        set_option(OPTION_ALLOW_PROXY_FALLBACK, "Y");
        for scheme in ["", "socks5://", "http://", "https://"] {
            set_option(OPTION_PROXY_URL, &format!("{scheme}{proxy_addr}"));
            let saved = Config::get_socks();
            let stream = connect_tcp(format!("localhost:{}", target_addr.port()), 1000)
                .await
                .unwrap();
            assert!(timeout(Duration::from_secs(1), target.accept())
                .await
                .is_ok());
            assert_eq!(Config::get_socks(), saved);
            assert!(get_socks_sync().is_none());
            drop(stream);
        }

        // An opt-out must take effect even while an unreachable result is cached.
        for disabled in ["", "N"] {
            set_option(OPTION_ALLOW_PROXY_FALLBACK, disabled);
            assert_eq!(get_socks().await, Config::get_socks());
            assert_eq!(get_socks_sync(), Config::get_socks());
            assert!(connect_tcp(target_addr, 300).await.is_err());
            assert!(timeout(Duration::from_millis(20), target.accept())
                .await
                .is_err());
        }

        set_option(OPTION_ALLOW_PROXY_FALLBACK, "Y");
        set_option(OPTION_PROXY_URL, &http_proxy);
        assert!(get_socks().await.is_none());
        let proxy_listener = proxy_socket.listen(8).unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = proxy_listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let len = stream.read(&mut request).await.unwrap();
                if len == 0 {
                    continue;
                }
                assert!(request[..len].starts_with(b"CONNECT "));
                stream
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        AVAILABILITY.lock().unwrap().as_mut().unwrap().checked_at = Instant::now() - CACHE_DURATION;
        assert!(get_socks().await.is_some());
        assert!(get_socks_sync().is_some());
        assert!(connect_tcp(target_addr, 1000).await.is_err());
        assert!(timeout(Duration::from_millis(20), target.accept())
            .await
            .is_err());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
