use crate::secret_store::{SecretStoreError, SecretStoreResult};

const ANDROID_SECRET_STORE_DISABLED: &str =
    "Android secret store is disabled; Android uses version 00 UUID-scoped encryption";

pub fn load_secret(_service: &str, _account: &str) -> SecretStoreResult<Vec<u8>> {
    Err(SecretStoreError::backend_message(
        "Android secret store is unavailable",
        ANDROID_SECRET_STORE_DISABLED,
    ))
}

pub fn store_secret(_service: &str, _account: &str, _secret: &[u8]) -> SecretStoreResult<()> {
    Err(SecretStoreError::backend_message(
        "Android secret store is unavailable",
        ANDROID_SECRET_STORE_DISABLED,
    ))
}
