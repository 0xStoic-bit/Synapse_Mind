//! Canlı bir çocuk sürecin tam bellek dökümü (`MiniDumpWriteDump`, MiniDumpWithFullMemory).

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Child;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    MINIDUMP_TYPE, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MiniDumpWithThreadInfo,
    MiniDumpWriteDump,
};

/// Silinmesi garanti edilen geçici dosya (Drop'ta silinir; panikte de).
pub struct TempFile(pub PathBuf);

impl TempFile {
    pub fn new(tag: &str, ext: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("s-gate2-{}-{n}-{tag}.{ext}", std::process::id())))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Silinmesi garanti edilen geçici dizin (şifreli deneme veritabanı için; Drop'ta özyinelemeli silinir).
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> io::Result<Self> {
        let f = TempFile::new(tag, "db");
        std::fs::create_dir_all(f.path())?;
        let p = f.path().to_path_buf();
        std::mem::forget(f); // dizin adı alındı; silme sorumluluğu TempDir'de
        Ok(Self(p))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `child` sürecinin tam bellek dökümünü `out` dosyasına yazar.
pub fn write_full_dump(child: &Child, out: &Path) -> io::Result<u64> {
    let file = File::create(out)?;
    let process = HANDLE(child.as_raw_handle());
    let file_handle = HANDLE(file.as_raw_handle());
    let dump_type = MINIDUMP_TYPE(
        MiniDumpWithFullMemory.0 | MiniDumpWithFullMemoryInfo.0 | MiniDumpWithThreadInfo.0,
    );
    // SAFETY: `process`, `child` yaşadığı sürece geçerli bir süreç tutamacıdır (std::process::Child
    // CreateProcess'ten PROCESS_ALL_ACCESS ile alır; `MiniDumpWriteDump` için gereken
    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ dahildir). `file_handle`, `file` yaşadığı sürece
    // yazılabilir geçerli bir dosya tutamacıdır. Üç isteğe bağlı işaretçi `None` (null) geçilir.
    // Her iki tutamacın sahipliği çağrılan tarafta kalır; fonksiyon bunları kapatmaz.
    unsafe {
        MiniDumpWriteDump(
            process,
            child.id(),
            file_handle,
            dump_type,
            None,
            None,
            None,
        )
        .map_err(|e| io::Error::other(format!("MiniDumpWriteDump: {e}")))?;
    }
    file.sync_all()?;
    Ok(file.metadata()?.len())
}
