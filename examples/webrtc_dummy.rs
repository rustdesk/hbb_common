use std::io::Error;

use bytes::BytesMut;

use hbb_common::ResultType;

/// Dummy implementation of WebRTCStream used when the `webrtc` feature is disabled.
/// This struct allows the code to compile and run without actual WebRTC functionality.
pub struct WebRTCStream {
    // mock struct
}

impl Clone for WebRTCStream {
    fn clone(&self) -> Self {
        WebRTCStream {}
    }
}

impl WebRTCStream {
    pub async fn new(_: &str, _: u64) -> ResultType<Self> {
        Ok(Self {})
    }

    #[inline]
    pub async fn get_local_endpoint(&self) -> ResultType<String> {
        Ok(String::new())
    }

    #[inline]
    pub async fn set_remote_endpoint(&self, _: &str) -> ResultType<()> {
        Ok(())
    }

    #[inline]
    pub async fn send_bytes(&mut self, _: bytes::Bytes) -> ResultType<()> {
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        None
    }
}


