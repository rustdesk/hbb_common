use crate::secret_store::SecretStoreResult;

pub fn load_secret(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    crate::platform::apple::load_secret_keychain_generic(service, account)
}

pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    crate::platform::apple::store_secret_keychain_generic(service, account, secret)
}
