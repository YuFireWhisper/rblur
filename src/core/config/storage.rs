use std::{
    collections::HashMap,
    fmt, fs,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, RwLock},
};

use thiserror::Error;

/// 儲存操作可能發生的錯誤類型。
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Key is invalid: {0}")]
    InvalidKey(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key is a dir: {0}")]
    IsDir(String),
    #[error("Not a directory: {0}")]
    NotDirectory(String),
    #[error("Lock poisoned")]
    LockPoisoned,
    #[error("File is corrupted")]
    CorruptedFile,
    #[error("Wildcard pattern is ambiguous: {0}")]
    AmbiguousPattern(String),
}

/// 儲存操作的結果類型。
pub type Result<T> = std::result::Result<T, StorageError>;

/// 儲存系統 API 定義。
pub trait Storage: Send + Sync + fmt::Debug {
    /// 建立指定目錄路徑（包含必要的父目錄）。
    fn create_dir_all(&self, key: &str) -> Result<()>;
    /// 以純文字 key 讀取檔案內容。
    /// 若 key 含萬用字元則會回傳錯誤，請改用 `read_files`。
    fn read_file(&self, key: &str) -> Result<Vec<u8>>;
    /// 根據萬用字元模式讀取符合條件的檔案，回傳檔名與內容的對應表。
    fn read_files(&self, pattern: &str) -> Result<HashMap<String, Vec<u8>>>;
    /// 寫入檔案內容。
    fn write_file(&self, key: &str, value: &[u8]) -> Result<()>;
    /// 刪除檔案或目錄（支援萬用字元模式）。
    fn remove(&self, key: &str) -> Result<()>;
    /// 檢查指定 key 是否存在。
    fn exists(&self, key: &str) -> Result<bool>;
    /// 判斷指定 key 是否為目錄。
    fn is_dir(&self, key: &str) -> Result<bool>;
    /// 遍歷指定目錄下的檔案（僅包含直接位於該目錄下的檔案）。
    fn traverse(&self, dir: &str) -> Result<HashMap<String, Vec<u8>>>;
    /// 獲取指定路徑下所有目錄的名稱。
    fn list_dirs(&self, dir: &str) -> Result<Vec<String>>;
    /// 獲取指定路徑下所有檔案的名稱。
    fn list_files(&self, dir: &str) -> Result<Vec<String>>;
}

/// 工具函式，提供 key 正規化、驗證與萬用字符匹配。
struct KeyUtils;

impl KeyUtils {
    /// 正規化 key 為絕對路徑，並檢查格式與不合法字元。
    fn normalize(key: &str) -> Result<PathBuf> {
        if key.is_empty() {
            return Err(StorageError::InvalidKey("Empty key".to_string()));
        }
        if key.contains('\0') || key.contains('\n') || key.contains('\r') {
            return Err(StorageError::InvalidKey(format!(
                "Invalid characters in key: {}",
                key
            )));
        }
        if key.contains("//") {
            return Err(StorageError::InvalidKey(format!(
                "Double slashes not allowed in key: {}",
                key
            )));
        }
        let path = Path::new(key);
        let mut normalized = PathBuf::from("/");
        for comp in path.components() {
            match comp {
                Component::RootDir => normalized = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    if normalized.as_os_str() == "/" {
                        return Err(StorageError::InvalidKey(format!(
                            "Cannot use '..' to escape root directory: {}",
                            key
                        )));
                    }
                    normalized.pop();
                }
                Component::Normal(name) => {
                    if let Some(s) = name.to_str() {
                        if s.contains('/') || s.contains('\\') {
                            return Err(StorageError::InvalidKey(format!(
                                "Invalid path component: {}",
                                s
                            )));
                        }
                        normalized.push(s);
                    } else {
                        return Err(StorageError::InvalidKey(format!(
                            "Non-UTF8 path component in: {}",
                            key
                        )));
                    }
                }
                _ => return Err(StorageError::InvalidKey(format!("Invalid path: {}", key))),
            }
        }
        Ok(normalized)
    }

    /// 取得指定路徑的父目錄。
    fn parent(path: &Path) -> Option<PathBuf> {
        path.parent().map(|p| p.to_path_buf())
    }

    /// 驗證目錄 key，確保其格式正確並以斜線結尾。
    fn verify_directory_key(key: &str) -> Result<PathBuf> {
        let mut path = Self::normalize(key)?;
        if !path.to_string_lossy().ends_with('/') {
            path.push("");
        }
        Ok(path)
    }

    /// 驗證檔案 key，確保其格式正確且不以斜線結尾。
    fn verify_file_key(key: &str) -> Result<PathBuf> {
        let path = Self::normalize(key)?;
        if key.ends_with('/') || path.to_string_lossy().ends_with('/') {
            return Err(StorageError::InvalidKey(format!(
                "File key cannot end with '/': {}",
                key
            )));
        }
        Ok(path)
    }

    /// 判斷字串中是否包含萬用字符 '*'
    fn contains_wildcard(s: &str) -> bool {
        s.contains('*')
    }

    /// 使用萬用字符模式比對 text，'*' 可匹配任意字元序列。
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let (p_bytes, t_bytes) = (pattern.as_bytes(), text.as_bytes());
        let (mut p, mut t) = (0, 0);
        let (mut star, mut match_index) = (None, 0);
        while t < t_bytes.len() {
            if p < p_bytes.len() && (p_bytes[p] == t_bytes[t] || p_bytes[p] == b'*') {
                if p_bytes[p] == b'*' {
                    star = Some(p);
                    match_index = t;
                    p += 1;
                    continue;
                }
                p += 1;
                t += 1;
            } else if let Some(star_pos) = star {
                p = star_pos + 1;
                match_index += 1;
                t = match_index;
            } else {
                return false;
            }
        }
        while p < p_bytes.len() && p_bytes[p] == b'*' {
            p += 1;
        }
        p == p_bytes.len()
    }
}

/// 基於檔案的儲存實作。
#[derive(Debug)]
pub struct FileStorage {
    index: Arc<RwLock<StorageIndex>>,
    file: Arc<RwLock<fs::File>>,
    file_path: PathBuf,
}

/// 儲存索引。
#[derive(Debug)]
struct StorageIndex {
    entries: HashMap<PathBuf, EntryMetadata>,
}

/// Entry 的元資料。
#[derive(Debug, Clone, Copy)]
struct EntryMetadata {
    offset: u64,
    is_dir: bool,
    is_deleted: bool,
}

impl FileStorage {
    /// 開啟或建立檔案儲存，並初始化根目錄與壓縮已刪除條目。
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file_path = path.as_ref().to_path_buf();
        let file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .read(true)
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&file_path)?
            }
        };

        let index = Self::build_index(&file)?;

        let storage = Self {
            index: Arc::new(RwLock::new(index)),
            file: Arc::new(RwLock::new(file)),
            file_path,
        };

        {
            let idx = storage
                .index
                .read()
                .map_err(|_| StorageError::LockPoisoned)?;
            if idx.entries.is_empty() {
                drop(idx);
                storage.write_entry(Path::new("/"), &[], true)?;
            }
        }

        storage.compress()?;

        Ok(storage)
    }

    fn build_index(file: &fs::File) -> Result<StorageIndex> {
        let mut reader = io::BufReader::new(file);
        let mut entries = HashMap::new();
        let mut offset = 0u64;
        loop {
            let entry_offset = offset;
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() || buffer.len() < 8 {
                break;
            }
            let header: [u8; 8] = buffer[..8].try_into().unwrap();
            reader.consume(8);
            offset += 8;
            let (key_len, flags) = Self::parse_header(&header);
            let mut key_buf = vec![0u8; key_len as usize];
            if let Err(e) = reader.read_exact(&mut key_buf) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return Err(e.into());
                }
            }
            offset += key_len as u64;
            let key = String::from_utf8_lossy(&key_buf);
            let path = KeyUtils::normalize(&key)?;
            let mut size_buf = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut size_buf) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return Err(e.into());
                }
            }
            offset += 4;
            let size = u32::from_le_bytes(size_buf);
            io::copy(&mut (&mut reader).take(size as u64), &mut io::sink())?;
            offset += size as u64;
            entries.insert(
                path,
                EntryMetadata {
                    offset: entry_offset,
                    is_dir: flags & 1 == 1,
                    is_deleted: flags & 2 == 2,
                },
            );
        }
        Ok(StorageIndex { entries })
    }

    fn parse_header(header: &[u8; 8]) -> (u32, u8) {
        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = header[4];
        (key_len, flags)
    }

    fn write_entry(&self, key: &Path, value: &[u8], is_dir: bool) -> Result<()> {
        let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
        let key_str = key.to_string_lossy();
        let key_bytes = key_str.as_bytes();
        let header = Self::create_header(key_bytes.len() as u32, is_dir, false);
        file.write_all(&header)?;
        file.write_all(key_bytes)?;
        let size = value.len() as u32;
        file.write_all(&size.to_le_bytes())?;
        file.write_all(value)?;
        let offset = file.stream_position()? - (size as u64 + key_bytes.len() as u64 + 12);
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
        index.entries.insert(
            key.to_path_buf(),
            EntryMetadata {
                offset,
                is_dir,
                is_deleted: false,
            },
        );
        Ok(())
    }

    fn create_header(key_len: u32, is_dir: bool, is_deleted: bool) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&key_len.to_le_bytes());
        header[4] = if is_dir { 1 } else { 0 } | if is_deleted { 2 } else { 0 };
        header
    }

    fn read_entry_at(&self, offset: u64) -> Result<(PathBuf, bool, Vec<u8>)> {
        let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let is_dir = header[4] & 1 == 1;
        let mut key_buf = vec![0u8; key_len as usize];
        file.read_exact(&mut key_buf)?;
        let key = KeyUtils::normalize(&String::from_utf8_lossy(&key_buf))?;
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let size = u32::from_le_bytes(size_buf);
        let mut value = vec![0u8; size as usize];
        file.read_exact(&mut value)?;
        Ok((key, is_dir, value))
    }

    fn compress(&self) -> Result<()> {
        let need_compress = {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            index.entries.values().any(|m| m.is_deleted)
        };
        if !need_compress {
            return Ok(());
        }
        let tmp_path = self.file_path.with_extension("tmp");
        let mut new_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        let mut new_index = HashMap::new();
        {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            let mut entries: Vec<(&PathBuf, EntryMetadata)> = index
                .entries
                .iter()
                .filter(|(_, meta)| !meta.is_deleted)
                .map(|(k, meta)| (k, *meta))
                .collect();
            entries.sort_by_key(|(_, meta)| meta.offset);
            for (key, _meta) in entries {
                let (entry_key, is_dir, value) = self.read_entry_at(
                    index
                        .entries
                        .get(key)
                        .ok_or_else(|| StorageError::NotFound(key.to_string_lossy().into_owned()))?
                        .offset,
                )?;
                let key_str = entry_key.to_string_lossy();
                let key_bytes = key_str.as_bytes();
                let header = Self::create_header(key_bytes.len() as u32, is_dir, false);
                new_file.write_all(&header)?;
                new_file.write_all(key_bytes)?;
                let size = value.len() as u32;
                new_file.write_all(&size.to_le_bytes())?;
                new_file.write_all(&value)?;
                let new_offset =
                    new_file.stream_position()? - (size as u64 + key_bytes.len() as u64 + 12);
                new_index.insert(
                    entry_key,
                    EntryMetadata {
                        offset: new_offset,
                        is_dir,
                        is_deleted: false,
                    },
                );
            }
            new_file.flush()?;
        }
        {
            drop(self.file.write().map_err(|_| StorageError::LockPoisoned)?);
            fs::rename(&tmp_path, &self.file_path)?;
            let new_f = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    fs::OpenOptions::new()
                        .read(true)
                        .append(true)
                        .mode(0o600)
                        .open(&self.file_path)?
                }
            };
            let mut file_lock = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            *file_lock = new_f;
        }
        {
            let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
            index.entries = new_index;
        }
        Ok(())
    }

    /// 讀取純文字 key 對應的檔案內容。
    fn read_file_literal(&self, path: &Path) -> Result<Vec<u8>> {
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        if let Some(metadata) = index.entries.get(path) {
            if metadata.is_deleted {
                return Err(StorageError::NotFound(path.to_string_lossy().into_owned()));
            }
            if metadata.is_dir {
                return Err(StorageError::IsDir(path.to_string_lossy().into_owned()));
            }
            drop(index);
            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            file.seek(SeekFrom::Start(
                self.index
                    .read()
                    .map_err(|_| StorageError::LockPoisoned)?
                    .entries
                    .get(path)
                    .unwrap()
                    .offset,
            ))?;
            let mut header = [0u8; 8];
            file.read_exact(&mut header)?;
            let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
            file.seek(SeekFrom::Current(key_len as i64))?;
            let mut size_buf = [0u8; 4];
            file.read_exact(&mut size_buf)?;
            let size = u32::from_le_bytes(size_buf);
            let mut data = vec![0u8; size as usize];
            file.read_exact(&mut data)?;
            Ok(data)
        } else {
            Err(StorageError::NotFound(path.to_string_lossy().into_owned()))
        }
    }
}

impl Storage for FileStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;
        let mut current = PathBuf::from("/");
        for comp in path.components().skip(1) {
            current.push(comp);
            let current_str = current.to_string_lossy();
            if self.exists(&current_str)? {
                if !self.is_dir(&current_str)? {
                    return Err(StorageError::NotDirectory(current_str.into_owned()));
                }
            } else {
                self.write_entry(&current, &[], true)?;
            }
        }
        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        if KeyUtils::contains_wildcard(key) {
            Err(StorageError::InvalidKey(
                "Wildcard pattern not allowed in read_file; use read_files instead".to_string(),
            ))
        } else {
            let path = KeyUtils::verify_file_key(key)?;
            self.read_file_literal(&path)
        }
    }

    fn read_files(&self, pattern: &str) -> Result<HashMap<String, Vec<u8>>> {
        let mut result = HashMap::new();
        if !KeyUtils::contains_wildcard(pattern) {
            let path = KeyUtils::verify_file_key(pattern)?;
            let content = self.read_file_literal(&path)?;
            result.insert(path.to_string_lossy().into_owned(), content);
            return Ok(result);
        }
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        let targets: Vec<PathBuf> = index
            .entries
            .iter()
            .filter(|(entry, meta)| {
                !meta.is_deleted
                    && !meta.is_dir
                    && KeyUtils::wildcard_match(pattern, &entry.to_string_lossy())
            })
            .map(|(entry, _)| entry.clone())
            .collect();
        drop(index);
        if targets.is_empty() {
            return Err(StorageError::NotFound(pattern.to_string()));
        }
        for target in targets {
            let content = self.read_file_literal(&target)?;
            result.insert(target.to_string_lossy().into_owned(), content);
        }
        Ok(result)
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        if KeyUtils::contains_wildcard(key) {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            let targets: Vec<PathBuf> = index
                .entries
                .iter()
                .filter(|(entry, meta)| {
                    !meta.is_deleted
                        && !meta.is_dir
                        && KeyUtils::wildcard_match(key, &entry.to_string_lossy())
                })
                .map(|(entry, _)| entry.clone())
                .collect();
            drop(index);
            if targets.is_empty() {
                return Err(StorageError::NotFound(key.to_string()));
            }
            for target in targets {
                self.write_entry(&target, value, false)?;
            }
            Ok(())
        } else {
            let path = KeyUtils::verify_file_key(key)?;
            if let Some(parent) = KeyUtils::parent(&path) {
                let parent_str = parent.to_string_lossy();
                if !self.exists(&parent_str)? {
                    self.create_dir_all(&parent_str)?;
                }
                if !self.is_dir(&parent_str)? {
                    return Err(StorageError::NotDirectory(parent_str.into_owned()));
                }
            }
            self.write_entry(&path, value, false)
        }
    }

    fn remove(&self, key: &str) -> Result<()> {
        if KeyUtils::contains_wildcard(key) {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            let targets: Vec<PathBuf> = index
                .entries
                .iter()
                .filter(|(entry, meta)| {
                    !meta.is_deleted && KeyUtils::wildcard_match(key, &entry.to_string_lossy())
                })
                .map(|(entry, _)| entry.clone())
                .collect();
            drop(index);
            if targets.is_empty() {
                return Err(StorageError::NotFound(key.to_string()));
            }
            for target in targets {
                let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
                if let Some(metadata) = index.entries.get_mut(&target) {
                    metadata.is_deleted = true;
                    let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
                    file.seek(SeekFrom::Start(metadata.offset + 4))?;
                    file.write_all(&[if metadata.is_dir { 3 } else { 2 }])?;
                }
            }
            Ok(())
        } else {
            let path = KeyUtils::normalize(key)?;
            let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
            if let Some(metadata) = index.entries.get_mut(&path) {
                metadata.is_deleted = true;
                let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
                file.seek(SeekFrom::Start(metadata.offset + 4))?;
                file.write_all(&[if metadata.is_dir { 3 } else { 2 }])?;
            }
            Ok(())
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        if KeyUtils::contains_wildcard(key) {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            Ok(index.entries.iter().any(|(entry, meta)| {
                !meta.is_deleted && KeyUtils::wildcard_match(key, &entry.to_string_lossy())
            }))
        } else {
            let path = KeyUtils::normalize(key)?;
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            Ok(index.entries.get(&path).is_some_and(|m| !m.is_deleted))
        }
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        if KeyUtils::contains_wildcard(key) {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            Ok(index.entries.iter().any(|(entry, meta)| {
                !meta.is_deleted
                    && meta.is_dir
                    && KeyUtils::wildcard_match(key, &entry.to_string_lossy())
            }))
        } else {
            let path = KeyUtils::normalize(key)?;
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            Ok(index
                .entries
                .get(&path)
                .is_some_and(|m| m.is_dir && !m.is_deleted))
        }
    }

    fn traverse(&self, dir: &str) -> Result<HashMap<String, Vec<u8>>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let mut result = HashMap::new();
        let matching_files: Vec<PathBuf> = {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            index
                .entries
                .iter()
                .filter(|(entry, meta)| {
                    !meta.is_deleted
                        && !meta.is_dir
                        && (KeyUtils::parent(entry).as_ref() == Some(&dir_path))
                })
                .map(|(entry, _)| entry.clone())
                .collect()
        };
        for file_path in matching_files {
            let content = self.read_file_literal(&file_path)?;
            result.insert(file_path.to_string_lossy().into_owned(), content);
        }
        Ok(result)
    }

    fn list_dirs(&self, dir: &str) -> Result<Vec<String>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;

        let dirs: Vec<String> = index
            .entries
            .iter()
            .filter(|(entry, meta)| {
                !meta.is_deleted
                    && meta.is_dir
                    && KeyUtils::parent(entry).as_ref() == Some(&dir_path)
            })
            .map(|(entry, _)| {
                entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        Ok(dirs)
    }

    fn list_files(&self, dir: &str) -> Result<Vec<String>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;

        let files: Vec<String> = index
            .entries
            .iter()
            .filter(|(entry, meta)| {
                !meta.is_deleted
                    && !meta.is_dir
                    && KeyUtils::parent(entry).as_ref() == Some(&dir_path)
            })
            .map(|(entry, _)| {
                entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        Ok(files)
    }
}

/// 基於記憶體的儲存實作。
#[derive(Debug)]
pub struct MemStorage {
    data: Arc<RwLock<HashMap<PathBuf, Vec<u8>>>>,
    dirs: Arc<RwLock<HashMap<PathBuf, ()>>>,
}

impl Default for MemStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStorage {
    /// 建立新的記憶體儲存實例並初始化根目錄 `/`。
    pub fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert(PathBuf::from("/"), ());
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            dirs: Arc::new(RwLock::new(dirs)),
        }
    }
}

impl Storage for MemStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;
        let mut current = PathBuf::from("/");
        let mut dirs = self.dirs.write().map_err(|_| StorageError::LockPoisoned)?;
        for comp in path.components().skip(1) {
            current.push(comp);
            if self
                .data
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&current)
            {
                return Err(StorageError::NotDirectory(
                    current.to_string_lossy().into_owned(),
                ));
            }
            dirs.entry(current.clone()).or_insert(());
        }
        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        if KeyUtils::contains_wildcard(key) {
            Err(StorageError::InvalidKey(
                "Wildcard pattern not allowed in read_file; use read_files instead".to_string(),
            ))
        } else {
            let path = KeyUtils::verify_file_key(key)?;
            let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
            data.get(&path)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))
        }
    }

    fn read_files(&self, pattern: &str) -> Result<HashMap<String, Vec<u8>>> {
        let mut result = HashMap::new();
        if !KeyUtils::contains_wildcard(pattern) {
            let path = KeyUtils::verify_file_key(pattern)?;
            let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
            let content = data
                .get(&path)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(pattern.to_string()))?;
            result.insert(path.to_string_lossy().into_owned(), content);
            return Ok(result);
        }
        let data_keys: Vec<PathBuf> = {
            let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
            data.keys()
                .filter(|k| KeyUtils::wildcard_match(pattern, &k.to_string_lossy()))
                .cloned()
                .collect()
        };
        if data_keys.is_empty() {
            return Err(StorageError::NotFound(pattern.to_string()));
        }
        let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
        for key in data_keys {
            if let Some(content) = data.get(&key) {
                result.insert(key.to_string_lossy().into_owned(), content.clone());
            }
        }
        Ok(result)
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        if KeyUtils::contains_wildcard(key) {
            let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
            let targets: Vec<PathBuf> = data
                .iter()
                .filter(|(k, _)| KeyUtils::wildcard_match(key, &k.to_string_lossy()))
                .map(|(k, _)| k.clone())
                .collect();
            drop(data);
            if targets.is_empty() {
                return Err(StorageError::NotFound(key.to_string()));
            }
            let mut data = self.data.write().map_err(|_| StorageError::LockPoisoned)?;
            for target in targets {
                data.insert(target, value.to_vec());
            }
            Ok(())
        } else {
            let path = KeyUtils::verify_file_key(key)?;
            if let Some(parent) = KeyUtils::parent(&path) {
                let parent_str = parent.to_string_lossy();
                if !self.exists(&parent_str)? {
                    self.create_dir_all(&parent_str)?;
                }
                if !self.is_dir(&parent_str)? {
                    return Err(StorageError::NotDirectory(parent_str.into_owned()));
                }
            }
            self.data
                .write()
                .map_err(|_| StorageError::LockPoisoned)?
                .insert(path, value.to_vec());
            Ok(())
        }
    }

    fn remove(&self, key: &str) -> Result<()> {
        if KeyUtils::contains_wildcard(key) {
            let data_keys: Vec<PathBuf> = {
                let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
                data.keys()
                    .filter(|k| KeyUtils::wildcard_match(key, &k.to_string_lossy()))
                    .cloned()
                    .collect()
            };
            let dir_keys: Vec<PathBuf> = {
                let dirs = self.dirs.read().map_err(|_| StorageError::LockPoisoned)?;
                dirs.keys()
                    .filter(|k| KeyUtils::wildcard_match(key, &k.to_string_lossy()))
                    .cloned()
                    .collect()
            };
            if data_keys.is_empty() && dir_keys.is_empty() {
                return Err(StorageError::NotFound(key.to_string()));
            }
            {
                let mut data = self.data.write().map_err(|_| StorageError::LockPoisoned)?;
                for k in data_keys {
                    data.remove(&k);
                }
            }
            {
                let mut dirs = self.dirs.write().map_err(|_| StorageError::LockPoisoned)?;
                for k in dir_keys {
                    dirs.remove(&k);
                }
            }
            Ok(())
        } else {
            let path = KeyUtils::normalize(key)?;
            self.data
                .write()
                .map_err(|_| StorageError::LockPoisoned)?
                .remove(&path);
            self.dirs
                .write()
                .map_err(|_| StorageError::LockPoisoned)?
                .remove(&path);
            Ok(())
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        if KeyUtils::contains_wildcard(key) {
            let data_exists = self
                .data
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .keys()
                .any(|k| KeyUtils::wildcard_match(key, &k.to_string_lossy()));
            let dir_exists = self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .keys()
                .any(|k| KeyUtils::wildcard_match(key, &k.to_string_lossy()));
            Ok(data_exists || dir_exists)
        } else {
            let path = KeyUtils::normalize(key)?;
            let data_exists = self
                .data
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&path);
            let dir_exists = self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&path);
            Ok(data_exists || dir_exists)
        }
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        if KeyUtils::contains_wildcard(key) {
            Ok(self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .keys()
                .any(|k| KeyUtils::wildcard_match(key, &k.to_string_lossy())))
        } else {
            let path = KeyUtils::normalize(key)?;
            Ok(self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&path))
        }
    }

    fn traverse(&self, dir: &str) -> Result<HashMap<String, Vec<u8>>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let mut result = HashMap::new();
        let matching_files: Vec<PathBuf> = {
            let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
            data.keys()
                .filter(|k| KeyUtils::parent(k).as_ref() == Some(&dir_path))
                .cloned()
                .collect()
        };
        for file_path in matching_files {
            let content = self.read_file(&file_path.to_string_lossy())?;
            result.insert(file_path.to_string_lossy().into_owned(), content);
        }
        Ok(result)
    }

    fn list_dirs(&self, dir: &str) -> Result<Vec<String>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let dirs = self.dirs.read().map_err(|_| StorageError::LockPoisoned)?;

        let subdirs: Vec<String> = dirs
            .keys()
            .filter(|entry| KeyUtils::parent(entry).as_ref() == Some(&dir_path))
            .map(|entry| {
                entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        Ok(subdirs)
    }

    fn list_files(&self, dir: &str) -> Result<Vec<String>> {
        let dir_path = KeyUtils::verify_directory_key(dir)?;
        let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;

        let files: Vec<String> = data
            .keys()
            .filter(|entry| KeyUtils::parent(entry).as_ref() == Some(&dir_path))
            .map(|entry| {
                entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        Ok(files)
    }
}
