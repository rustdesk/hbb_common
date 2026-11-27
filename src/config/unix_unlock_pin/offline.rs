use super::{Config, Config2, RootPin};
use crate::ResultType;
use std::path::PathBuf;

impl RootPin {
    /// Names beneath the macOS account's Preferences directory, for the offline reader.
    pub fn offline_config_names() -> ResultType<[PathBuf; 3]> {
        let preferences = Config::get_home().join("Library/Preferences");
        let directory = Config::path("");
        Ok([
            directory.strip_prefix(preferences)?.to_owned(),
            Config::file_("_unlock_pin")
                .strip_prefix(&directory)?
                .to_owned(),
            Config2::file().strip_prefix(&directory)?.to_owned(),
        ])
    }
}
