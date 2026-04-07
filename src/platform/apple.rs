use crate::secret_store::{SecretStoreError, SecretStoreResult};
use security_framework::passwords::{generic_password, set_generic_password, PasswordOptions};

// errSecItemNotFound from Apple Security Framework (defined in SecBase.h)
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/base/SecBase.h#L353
// Chromium similarly only special-cases `errSecItemNotFound`; other keychain
// errors are logged and returned to the caller unchanged:
// https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm#97
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
// In the normal same-signing app flow this should not happen. Apple documents
// that permissions can be lost after corruption or upgrades:
// https://support.apple.com/en-lk/guide/keychain-access/kyca1331/mac
// If the user manually denies the request, treat it as sticky and stop reading
// the keychain again after recording the failure.
const ERR_SEC_USER_CANCELED: i32 = -128;

pub(crate) fn map_keychain_result<T>(
    result: security_framework::base::Result<T>,
    context: &'static str,
) -> SecretStoreResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Err(SecretStoreError::NotFound),
        Err(err) if err.code() == ERR_SEC_USER_CANCELED => {
            Err(SecretStoreError::user_canceled(context, err))
        }
        Err(err) => Err(SecretStoreError::backend(context, err)),
    }
}

pub fn load_secret_keychain_generic(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    // https://developer.apple.com/documentation/security/secitemcopymatching
    // Chromium: https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm
    map_keychain_result(
        generic_password(PasswordOptions::new_generic_password(service, account)),
        "failed to read secret from Apple generic keychain",
    )
}

pub fn store_secret_keychain_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    // https://developer.apple.com/documentation/security/secitemadd
    // https://developer.apple.com/documentation/security/secitemupdate
    // Chromium: https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm
    map_keychain_result(
        set_generic_password(service, account, secret),
        "failed to write secret to Apple generic keychain",
    )?;
    Ok(())
}
