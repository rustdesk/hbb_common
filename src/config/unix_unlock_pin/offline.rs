use super::{try_load_path, RootPin};
use crate::{anyhow::anyhow, ResultType};
use confy::ConfyError;
use std::{io::ErrorKind, path::Path};

#[cfg(target_os = "macos")]
impl RootPin {
    pub fn configured_without_migration() -> ResultType<bool> {
        let (file, legacy) = super::root_paths()?;
        configured_on_disk(&file, &legacy)
    }
}

fn configured_on_disk(file: &Path, legacy: &Path) -> ResultType<bool> {
    match confy::load_path::<RootPin>(file) {
        Ok(pin) => return Ok(pin.configured()),
        Err(ConfyError::GeneralLoadError(err)) if err.kind() == ErrorKind::NotFound => (),
        Err(ConfyError::BadTomlData(_)) => return Err(anyhow!("Invalid root PIN configuration")),
        Err(err) => return Err(err.into()),
    }
    let settings: toml::Table = try_load_path(legacy.to_path_buf())?;
    match settings.get("unlock_pin") {
        None => Ok(false),
        Some(toml::Value::String(pin)) => Ok(!pin.is_empty()),
        Some(_) => Err(anyhow!("Invalid legacy unlock PIN")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn offline_pin_status_reads_without_migrating() {
        let dir = std::env::temp_dir().join(format!("rd-offline-pin-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("root-pin.toml");
        let legacy = dir.join("root-config.toml");
        let configured = || configured_on_disk(&file, &legacy);
        assert!(!configured().unwrap());
        assert!(!file.exists() && !legacy.exists());
        fs::write(&legacy, "serial = 7").unwrap();
        assert!(!configured().unwrap());
        fs::write(&legacy, "unlock_pin = 7").unwrap();
        assert!(configured().is_err());
        fs::write(&legacy, "unlock_pin = 'old'").unwrap();
        assert!(configured().unwrap());
        assert!(!file.exists());
        assert_eq!(fs::read_to_string(&legacy).unwrap(), "unlock_pin = 'old'");
        fs::write(&file, "unlock_pin = ''").unwrap();
        assert!(!configured().unwrap());
        fs::write(&file, "unlock_pin = 'set'").unwrap();
        assert!(configured().unwrap());
        fs::write(&file, "[").unwrap();
        assert!(configured().is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
