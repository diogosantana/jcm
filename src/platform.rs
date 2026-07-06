use std::path::{Path, PathBuf};

pub fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unknown"
    }
}

pub fn is_interactive_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
pub fn is_root() -> bool {
    use std::mem::MaybeUninit;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
        let mut size = 0u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            elevation.as_mut_ptr().cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) == 0
        {
            return false;
        }
        elevation.assume_init().TokenIsElevated != 0
    }
}

#[cfg(not(any(unix, windows)))]
pub fn is_root() -> bool {
    false
}

#[cfg(unix)]
pub fn set_private_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(unix)]
pub fn set_private_file_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
pub fn set_private_dir_perms(_path: &Path) {}

#[cfg(not(unix))]
pub fn set_private_file_perms(_path: &Path) {}

pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}
