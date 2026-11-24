use super::{
    decrypt_str_or_original, encrypt_str_or_original, store_path, try_load_path, Config, Config2,
    CONFIG2, ENCRYPT_MAX_LEN, PASSWORD_ENC_VERSION,
};
use crate::{
    anyhow::{anyhow, ensure},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Default, Deserialize, Serialize)]
pub struct RootPin {
    unlock_pin: String,
}

impl RootPin {
    pub fn configured(&self) -> bool {
        !self.unlock_pin.is_empty()
    }

    fn from_pin(pin: &str) -> ResultType<Self> {
        if pin.is_empty() {
            return Ok(Self::default());
        }
        let encrypted = encrypt_str_or_original(pin, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        let (plain, decoded, _) = decrypt_str_or_original(&encrypted, PASSWORD_ENC_VERSION);
        ensure!(
            decoded && plain == pin,
            "Could not encode the root unlock PIN"
        );
        Ok(Self {
            unlock_pin: encrypted,
        })
    }

    pub fn matches(&self, candidate: &str) -> ResultType<bool> {
        if !self.configured() {
            return Ok(false);
        }
        let (pin, decoded, _) = decrypt_str_or_original(&self.unlock_pin, PASSWORD_ENC_VERSION);
        ensure!(decoded, "Could not decode the root unlock PIN");
        Ok(sodiumoxide::utils::memcmp(
            pin.as_bytes(),
            candidate.as_bytes(),
        ))
    }

    pub fn load() -> ResultType<Self> {
        let (file, legacy) = root_paths()?;
        let mut current = CONFIG2.write().unwrap();
        let pin = load_or_migrate(&file, &legacy)?;
        current.unlock_pin.clear();
        Ok(pin)
    }

    pub fn set(pin: &str) -> ResultType<()> {
        let (file, _) = root_paths()?;
        store_path(file, Self::from_pin(pin)?)
    }
}

fn root_paths() -> ResultType<(PathBuf, PathBuf)> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "The root service must own the unlock PIN"
    );
    let legacy = Config2::file();
    let dir = legacy
        .parent()
        .ok_or_else(|| anyhow!("Missing root config directory"))?;
    ensure!(dir.is_absolute(), "Missing absolute root config directory");
    // The system service may be started with HOME or XDG_CONFIG_HOME from its caller.
    // Refuse a user-controlled directory before creating or reading either PIN file.
    for ancestor in dir.ancestors() {
        match fs::metadata(ancestor) {
            Ok(meta) => ensure!(
                meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.is_dir(),
                "Unsafe root configuration directory: {}",
                ancestor.display()
            ),
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        }
    }
    let file = Config::file_("_unlock_pin");
    for path in [&file, &legacy] {
        match fs::symlink_metadata(path) {
            Ok(meta) => ensure!(
                meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
                "Unsafe root PIN configuration file: {}",
                path.display()
            ),
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            Err(err) => return Err(err.into()),
        }
    }
    Ok((file, legacy))
}

fn read_legacy(path: &Path) -> ResultType<Config2> {
    try_load_path(path.to_path_buf())
}

fn clear_legacy(path: &Path, stored: Config2) -> ResultType<()> {
    if !stored.unlock_pin.is_empty() {
        store_path(path.to_path_buf(), stored.without_unlock_pin())?;
    }
    Ok(())
}

fn load_or_migrate(file: &Path, legacy: &Path) -> ResultType<RootPin> {
    if file.try_exists()? {
        return try_load_path(file.to_path_buf());
    }
    let stored = read_legacy(legacy)?;
    let (pin, decoded, legacy_plain) =
        decrypt_str_or_original(&stored.unlock_pin, PASSWORD_ENC_VERSION);
    ensure!(
        stored.unlock_pin.is_empty() || decoded || legacy_plain,
        "Could not migrate the legacy root unlock PIN"
    );
    let value = RootPin::from_pin(&pin)?;
    // An empty authority file also marks migration complete after removal or a fresh install.
    store_path(file.to_path_buf(), &value)?;
    clear_legacy(legacy, stored)?;
    Ok(value)
}

pub fn discard_user_copy() -> ResultType<()> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Cannot discard the root PIN as a user copy"
    );
    let mut current = CONFIG2.write().unwrap();
    let path = Config2::file();
    clear_legacy(&path, read_legacy(&path)?)?;
    current.unlock_pin.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_root_profile_supplies_the_initial_pin() {
        let dir = std::env::temp_dir().join(format!("rd-root-pin-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let authority = dir.join("root-pin.toml");
        let legacy = dir.join("root-config.toml");
        let user = dir.join("user-config.toml");
        let fixture = Config2 {
            unlock_pin: "user-only".into(),
            ..Default::default()
        };
        store_path(user, fixture).unwrap();
        assert!(load_or_migrate(&authority, &legacy)
            .unwrap()
            .unlock_pin
            .is_empty());
        std::fs::remove_file(&authority).unwrap();
        store_path(
            legacy.clone(),
            Config2 {
                unlock_pin: "old-root".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(load_or_migrate(&authority, &legacy)
            .unwrap()
            .matches("old-root")
            .unwrap());
        assert!(read_legacy(&legacy).unwrap().unlock_pin.is_empty());
        let mut stale = read_legacy(&legacy).unwrap();
        stale.unlock_pin = "stale".into();
        store_path(legacy.clone(), stale).unwrap();
        assert!(load_or_migrate(&authority, &legacy)
            .unwrap()
            .matches("old-root")
            .unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
