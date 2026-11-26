use super::{Config, Config2, CONFIG2};
use std::collections::HashMap;

impl Config2 {
    fn preserve_option(&self, options: &mut HashMap<String, String>, key: &str) {
        if let Some(value) = self.options.get(key) {
            options.insert(key.to_owned(), value.clone());
        } else {
            options.remove(key);
        }
    }

    /// Replaces the configuration while retaining the locally stored entry for `key`.
    pub fn set_preserving_option(mut incoming: Self, key: &str) -> bool {
        let mut current = CONFIG2.write().unwrap();
        current.preserve_option(&mut incoming.options, key);
        if *current == incoming {
            return false;
        }
        *current = incoming;
        current.store();
        true
    }
}

impl Config {
    /// Replaces the options while retaining the locally stored entry for `key`.
    pub fn set_options_preserving_option(mut options: HashMap<String, String>, key: &str) {
        Self::purify_options(&mut options);
        let mut current = CONFIG2.write().unwrap();
        current.preserve_option(&mut options, key);
        if current.options != options {
            current.options = options;
            current.store();
        }
    }
}
