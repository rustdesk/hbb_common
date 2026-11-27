use super::Config2;
use crate::{
    anyhow::{anyhow, ensure},
    ResultType,
};
use serde_derive::Deserialize;
use std::{
    fs::{File, OpenOptions, Permissions},
    io::{self, ErrorKind, Read},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn open_for_cleanup(path: &Path) -> io::Result<File> {
    const OWNER_WRITE: u32 = 0o200;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let denied = match options.write(true).open(path) {
        Err(err) if err.kind() == ErrorKind::PermissionDenied => err,
        result => return result,
    };
    let original = options.write(false).open(path)?;
    let meta = original.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & OWNER_WRITE != 0
    {
        return Err(denied);
    }
    // Only the open needs owner-write. Restore the mode on the original inode
    // before using the descriptor, even if the path was replaced or the open failed.
    original.set_permissions(Permissions::from_mode(meta.mode() | OWNER_WRITE))?;
    let writable = options.write(true).open(path);
    original.set_permissions(meta.permissions())?;
    writable
}

pub(super) fn clear(path: &Path, stored: Config2) -> ResultType<()> {
    #[derive(Deserialize)]
    struct LegacyPin {
        unlock_pin: Option<toml::Spanned<String>>,
    }

    if stored.unlock_pin.is_empty() {
        return Ok(());
    }
    loop {
        let mut file = match open_for_cleanup(path) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        ensure!(file.metadata()?.is_file(), "Expected a regular config file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let snapshot: LegacyPin =
            toml::from_str(&contents).map_err(|_| anyhow!("Invalid legacy PIN configuration"))?;
        if let Some(pin) = snapshot.unlock_pin.filter(|pin| !pin.get_ref().is_empty()) {
            let span = pin.span();
            let mut empty = b"''".to_vec();
            empty.resize(span.len(), b' ');
            file.write_all_at(&empty, span.start as u64)?;
        }
        // Config writers publish by rename. If a newer file replaced this inode,
        // clear its PIN too without writing back any of the older settings.
        if file.metadata()?.nlink() != 0 {
            return Ok(());
        }
    }
}
