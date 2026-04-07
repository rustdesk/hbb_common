#[cfg(not(target_os = "windows"))]
use crate::{
    config::{self, APP_NAME},
    log,
};
#[cfg(not(target_os = "windows"))]
use once_cell::sync::OnceCell;

const MASTER_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;
#[cfg(not(target_os = "windows"))]
const SAFE_STORAGE_SUFFIX: &str = " Safe Storage";
const USER_DATA_MAGIC_HEADER: [u8; 16] = [
    0xbe, 0xb6, 0x88, 0x39, 0x41, 0x15, 0x4b, 0xe7, 0x8d, 0x94, 0x10, 0x23, 0x59, 0x8f, 0x8b, 0x24,
];

#[cfg(not(target_os = "windows"))]
static MASTER_KEY: OnceCell<Result<sodiumoxide::crypto::secretbox::Key, CachedSecretStoreError>> =
    OnceCell::new();

pub type SecretStoreResult<T> = Result<T, SecretStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("secret not found")]
    NotFound,
    #[error("{context}: {message}")]
    Invalid {
        context: &'static str,
        message: String,
    },
    #[error("{context}: user canceled")]
    UserCanceled {
        context: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("{context}: {source}")]
    Backend {
        context: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

impl SecretStoreError {
    pub fn backend(context: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self::Backend {
            context,
            source: source.into(),
        }
    }

    pub fn backend_message(context: &'static str, message: impl Into<String>) -> Self {
        Self::Backend {
            context,
            source: anyhow::Error::msg(message.into()),
        }
    }

    pub fn invalid(context: &'static str, message: impl Into<String>) -> Self {
        Self::Invalid {
            context,
            message: message.into(),
        }
    }

    pub fn user_canceled(context: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self::UserCanceled {
            context,
            source: source.into(),
        }
    }

    pub(crate) fn is_user_canceled(&self) -> bool {
        matches!(self, Self::UserCanceled { .. })
    }
}

#[derive(Debug, Clone)]
enum CachedSecretStoreError {
    NotFound,
    Invalid {
        context: &'static str,
        message: String,
    },
    UserCanceled {
        context: &'static str,
        message: String,
    },
    Backend {
        context: &'static str,
        message: String,
    },
}

impl From<SecretStoreError> for CachedSecretStoreError {
    fn from(err: SecretStoreError) -> Self {
        match err {
            SecretStoreError::NotFound => Self::NotFound,
            SecretStoreError::Invalid { context, message } => Self::Invalid { context, message },
            SecretStoreError::UserCanceled { context, source } => Self::UserCanceled {
                context,
                message: source.to_string(),
            },
            SecretStoreError::Backend { context, source } => Self::Backend {
                context,
                message: source.to_string(),
            },
        }
    }
}

impl CachedSecretStoreError {
    fn to_secret_store_error(&self) -> SecretStoreError {
        match self {
            Self::NotFound => SecretStoreError::NotFound,
            Self::Invalid { context, message } => {
                SecretStoreError::invalid(context, message.clone())
            }
            Self::UserCanceled { context, message } => {
                SecretStoreError::user_canceled(context, anyhow::Error::msg(message.clone()))
            }
            Self::Backend { context, message } => {
                SecretStoreError::backend_message(context, message.clone())
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_or_init_cached_secret<T, F>(
    cache: &OnceCell<Result<T, CachedSecretStoreError>>,
    init: F,
) -> SecretStoreResult<&T>
where
    F: FnOnce() -> SecretStoreResult<T>,
{
    match cache.get_or_init(|| init().map_err(CachedSecretStoreError::from)) {
        Ok(value) => Ok(value),
        Err(err) => Err(err.to_secret_store_error()),
    }
}

pub(crate) fn user_data_magic_header() -> &'static [u8] {
    &USER_DATA_MAGIC_HEADER
}

pub(crate) fn user_data_has_magic_header(payload: &[u8]) -> bool {
    payload.starts_with(user_data_magic_header())
}

pub(crate) fn user_data_add_magic_header(mut payload: Vec<u8>) -> Vec<u8> {
    let mut out = user_data_magic_header().to_vec();
    out.append(&mut payload);
    out
}

pub(crate) fn user_data_strip_magic_header(payload: &[u8]) -> (&[u8], bool) {
    if let Some(payload) = payload.strip_prefix(user_data_magic_header()) {
        (payload, true)
    } else {
        (payload, false)
    }
}

pub(crate) fn is_encrypted_user_data(payload: &[u8]) -> bool {
    user_data_has_magic_header(payload)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn secretbox_encrypt_user_data_raw(
    data: &[u8],
) -> Result<Vec<u8>, crate::password_security::CryptError> {
    use sodiumoxide::crypto::secretbox;

    let key = master_secretbox_key()
        .map_err(|_| crate::password_security::CryptError::EncryptionFailed)?;
    let nonce = secretbox::gen_nonce();
    let mut out = nonce.0.to_vec();
    out.extend(secretbox::seal(data, &nonce, key));
    Ok(out)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn secretbox_decrypt_user_data_raw(
    data: &[u8],
) -> Result<Vec<u8>, crate::password_security::CryptError> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    if data.len() < secretbox_user_data_min_len() {
        return Err(crate::password_security::CryptError::InvalidData);
    }
    let key = master_secretbox_key()
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)?;
    let nonce = secretbox::Nonce(
        data[..secretbox::NONCEBYTES]
            .try_into()
            .map_err(|_| crate::password_security::CryptError::InvalidData)?,
    );
    secretbox::open(&data[secretbox::NONCEBYTES..], &nonce, key)
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)
}

#[cfg(not(target_os = "windows"))]
fn secretbox_user_data_min_len() -> usize {
    sodiumoxide::crypto::secretbox::NONCEBYTES + sodiumoxide::crypto::secretbox::MACBYTES
}

#[cfg(not(target_os = "windows"))]
fn master_secretbox_key() -> SecretStoreResult<&'static sodiumoxide::crypto::secretbox::Key> {
    // Cache key load/failure to avoid repeatedly blocking on broken secret backend.
    get_or_init_cached_secret(&MASTER_KEY, load_or_create_master_secretbox_key)
}

#[cfg(not(target_os = "windows"))]
fn should_regenerate_master_secret(err: &SecretStoreError) -> bool {
    matches!(
        err,
        SecretStoreError::NotFound | SecretStoreError::Invalid { .. }
    )
}

#[cfg(not(target_os = "windows"))]
fn current_secret_store_names(app_name: &str) -> (String, String) {
    (
        format!("{app_name}{SAFE_STORAGE_SUFFIX}"),
        app_name.to_owned(),
    )
}

#[cfg(not(target_os = "windows"))]
fn should_mark_skip_load(err: &SecretStoreError) -> bool {
    err.is_user_canceled()
}

#[cfg(not(target_os = "windows"))]
fn load_or_create_master_secretbox_key() -> SecretStoreResult<sodiumoxide::crypto::secretbox::Key> {
    use std::convert::TryInto;

    if config::SecretStatus::load().should_skip_load() {
        let err = SecretStoreError::backend_message(
            "skipping system secret store access",
            "system secret store initialization was previously marked as failed",
        );
        log::warn!("{err}");
        return Err(err);
    }

    let app_name = APP_NAME.read().unwrap().clone();
    let (service, account) = current_secret_store_names(&app_name);
    let create_and_store_key = || -> SecretStoreResult<Vec<u8>> {
        log::info!(
            "Generating new {} byte key for system secret store (service: {}, account: {})",
            MASTER_KEY_LEN,
            service,
            account
        );
        let key = sodiumoxide::randombytes::randombytes(MASTER_KEY_LEN);
        if let Err(err) = store_secret(&service, &account, &key) {
            log::error!("Failed to persist generated master key: {err}");
            return Err(err);
        }
        let stored = match load_secret(&service, &account, MASTER_KEY_LEN) {
            Ok(stored) => stored,
            Err(err) => {
                log::warn!("failed to reload master key after storing it: {err}");
                return Err(err);
            }
        };
        if stored != key {
            let err = SecretStoreError::invalid(
                "stored master key verification failed",
                "reloaded secret does not match the generated key",
            );
            log::warn!("stored master key verification failed: {err}");
            return Err(err);
        }
        log::info!("Successfully created and stored new master key in system secret store");
        Ok(key)
    };
    let keybuf = match load_secret(&service, &account, MASTER_KEY_LEN) {
        Ok(key) => {
            log::info!(
                "Loaded existing master key from system secret store (service: {}, account: {})",
                service,
                account
            );
            key
        }
        Err(err) if should_regenerate_master_secret(&err) => {
            log::warn!(
                "Stored master key is missing or invalid, regenerating it (service: {}, account: {}, reason: {})",
                service,
                account,
                err
            );
            create_and_store_key()?
        }
        Err(err) => {
            log::error!("Failed to load master key: {err}");
            if should_mark_skip_load(&err) {
                config::SecretStatus::mark_skip_load();
            }
            return Err(err);
        }
    };
    let actual = keybuf.len();
    Ok(sodiumoxide::crypto::secretbox::Key(
        keybuf.try_into().map_err(|_| {
            SecretStoreError::invalid(
                "stored secret has invalid length",
                format!("expected {MASTER_KEY_LEN} bytes, got {actual}"),
            )
        })?,
    ))
}

#[cfg(not(target_os = "windows"))]
fn load_secret(service: &str, account: &str, expected_len: usize) -> SecretStoreResult<Vec<u8>> {
    with_expected_len(crate::platform::load_secret(service, account), expected_len)
}

#[cfg(not(target_os = "windows"))]
fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    crate::platform::store_secret(service, account, secret)
}

fn with_expected_len(
    secret: SecretStoreResult<Vec<u8>>,
    expected_len: usize,
) -> SecretStoreResult<Vec<u8>> {
    let secret = secret?;
    if secret.len() == expected_len {
        Ok(secret)
    } else {
        Err(SecretStoreError::invalid(
            "stored secret has invalid length",
            format!("expected {expected_len} bytes, got {}", secret.len()),
        ))
    }
}
