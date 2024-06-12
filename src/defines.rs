// Process Creation (https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
pub static CREATE_NO_WINDOW: u32 = 0x08000000;
pub static CREATE_SUSPENDED: u32 = 0x00000004;
pub static EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;

// File Access Rights (https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights)
pub static GENERIC_ALL: u32 = 0x10000000;
pub static GENERIC_EXECUTE: u32 = 0x20000000;
pub static GENERIC_WRITE: u32 = 0x40000000;
pub static GENERIC_READ: u32 = 0x80000000;

// File Share Rights (https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
// I know that this is retarded but in the microsoft documentation this is the name of the flag I
// just added file before it. Don't hate the player.
pub static FILE_0: u32 = 0x00000000;
pub static FILE_SHARE_DELETE: u32 = 0x00000004;
pub static FILE_SHARE_READ: u32 = 0x00000001;
pub static FILE_SHARE_WRITE: u32 = 0x00000002;

// File Creation Disposition (https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
// No I dont know why these are just normal integers
pub static CREATE_ALWAYS: u32 = 2;
pub static CREATE_NEW: u32 = 1;
pub static OPEN_ALWAYS: u32 = 4;
pub static OPEN_EXISTING: u32 = 3;
pub static TRUNCATE_EXISTING: u32 = 5;

// File Attributes (https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)
pub static FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub static FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
pub static FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub static FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub static FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub static FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub static FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub static FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;

pub static FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
pub static FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000;
pub static FILE_FLAG_NO_BUFFERING: u32 = 0x20000000;
pub static FILE_FLAG_OPEN_NO_RECALL: u32 = 0x00100000;
pub static FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
pub static FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
pub static FILE_FLAG_POSIX_SEMANTICS: u32 = 0x01000000;
pub static FILE_FLAG_RANDOM_ACCESS: u32 = 0x10000000;
pub static FILE_FLAG_SESSION_AWARE: u32 = 0x00800000;
pub static FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x08000000;
pub static FILE_FLAG_WRITE_THROUGH: u32 = 0x80000000;
