use crate::{anyhow::Context, ResultType};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

pub struct FileStorage {
    path: PathBuf,
    _lock: File,
}

impl FileStorage {
    pub fn lock(path: &Path) -> ResultType<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| crate::anyhow::anyhow!("Missing credential directory"))?;
        let mut directories = fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(PRIVATE_DIRECTORY_MODE);
        }
        directories
            .create(parent)
            .context("Create trusted-device credential directory")?;
        let lock = lock_file(&path.with_extension("lock"))?;
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }

    pub fn read<T: DeserializeOwned + Default>(&self) -> ResultType<T> {
        match File::open(&self.path) {
            Ok(file) => serde_json::from_reader(file).context("Read trusted-device credentials"),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(T::default()),
            Err(error) => Err(error).context("Open trusted-device credentials"),
        }
    }

    pub fn read_toml<T: DeserializeOwned + Default>(&self) -> ResultType<T> {
        match fs::read_to_string(&self.path) {
            Ok(value) => crate::toml::from_str(&value)
                .map_err(|_| crate::anyhow::anyhow!("Invalid configuration file")),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(T::default()),
            Err(error) => Err(error).context("Open configuration file"),
        }
    }

    pub fn write_toml<T: Serialize>(&self, value: &T) -> ResultType<()> {
        let value = crate::toml::to_string(value).context("Encode configuration update")?;
        self.write_with(|file| Ok(file.write_all(value.as_bytes())?))
    }

    pub fn write<T: Serialize>(&self, value: &T) -> ResultType<()> {
        self.write_with(|file| {
            serde_json::to_writer(file, value).context("Encode trusted-device credential update")
        })
    }

    fn write_with(&self, write: impl FnOnce(&mut File) -> ResultType<()>) -> ResultType<()> {
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", crate::uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(PRIVATE_FILE_MODE);
        }
        let mut file = options
            .open(&temporary)
            .context("Create trusted-device credential update")?;
        write(&mut file)?;
        file.sync_all()
            .context("Persist trusted-device credential update")?;
        #[cfg(not(windows))]
        fs::rename(&temporary, &self.path).context("Commit trusted-device credential update")?;
        #[cfg(windows)]
        replace_file(&temporary, &self.path)?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            File::open(parent)?
                .sync_all()
                .context("Persist trusted-device credential directory")?;
        }
        Ok(())
    }
}

fn lock_file(path: &Path) -> ResultType<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(crate::libc::O_NOFOLLOW | crate::libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
    }
    let file = options
        .open(path)
        .context("Lock trusted-device credentials")?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let result = unsafe { crate::libc::flock(file.as_raw_fd(), crate::libc::LOCK_EX) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("Lock trusted-device credentials");
        }
    }
    #[cfg(windows)]
    lock_windows_file(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn lock_windows_file(file: &File) -> ResultType<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{Foundation::HANDLE, Storage::FileSystem, System::IO::OVERLAPPED};
    const LOCK_BYTES: u32 = 1;
    // This is a synchronous handle: wait for the lock; closing the handle releases it.
    unsafe {
        FileSystem::LockFileEx(
            HANDLE(file.as_raw_handle()),
            FileSystem::LOCKFILE_EXCLUSIVE_LOCK,
            None,
            LOCK_BYTES,
            0,
            &mut OVERLAPPED::default(),
        )
    }
    .context("Lock trusted-device credentials")
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> ResultType<()> {
    use windows::{core::HSTRING, Win32::Storage::FileSystem};
    unsafe {
        FileSystem::MoveFileExW(
            &HSTRING::from(source),
            &HSTRING::from(destination),
            FileSystem::MOVEFILE_REPLACE_EXISTING | FileSystem::MOVEFILE_WRITE_THROUGH,
        )
    }
    .context("Commit trusted-device credential update")
}
