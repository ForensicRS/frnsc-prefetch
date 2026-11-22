//! The prefetch path hash: the 32-bit value in a prefetch file's header and file name
//! (`CMD.EXE-087B4001.pf`), computed by Windows over the executable's upper-case device path
//! (`\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE`) as UTF-16 little-endian bytes, with no
//! terminating NUL.
//!
//! Written from libscca's "Windows Prefetch File (PF) format" documentation
//! (<https://github.com/libyal/libscca/tree/main/documentation>). Windows XP and 2003 (format
//! version 17) use the "XP" function. Vista, 7, 8 and 10 (23 and later) use the "Vista" function;
//! the document's separate "2008" function is an unrolled form of it that gives the same values.
//! Hosted executables (`SVCHOST.EXE`, `DLLHOST.EXE`, `RUNDLL32.EXE`, `MMC.EXE`, ...) mix their
//! command line into the hash, so their path alone does not reproduce it.

/// Bytes the hash is computed over: the path's UTF-16 little-endian encoding.
fn utf16le(path: &str) -> impl Iterator<Item = u32> + '_ {
    path.encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .map(u32::from)
}

/// The hash Windows XP and 2003 (format version 17) use.
pub fn scca_xp_hash(path: &str) -> u32 {
    let mut hash = 0u32;
    for byte in utf16le(path) {
        hash = hash.wrapping_mul(37).wrapping_add(byte);
    }
    let mut hash = hash.wrapping_mul(314_159_269);
    if hash > 0x8000_0000 {
        hash = hash.wrapping_neg();
    }
    hash % 1_000_000_007
}

/// The hash Windows Vista and later (format version 23 and later) use.
pub fn scca_vista_hash(path: &str) -> u32 {
    let mut hash = 314_159u32;
    for byte in utf16le(path) {
        hash = hash.wrapping_mul(37).wrapping_add(byte);
    }
    hash
}

/// The path hash of `device_path` as a file of format `version` stores it. The path is hashed
/// as given: prefetch files store their paths upper-case already.
pub fn scca_hash(version: u32, device_path: &str) -> u32 {
    if version == 17 {
        scca_xp_hash(device_path)
    } else {
        scca_vista_hash(device_path)
    }
}

/// Whether the file whose loaded path is `path` hashes to `hash` in format `version`.
///
/// A version 30 or later path names its volume as `\VOLUME{<creation time>-<serial>}`, but
/// Windows still hashes the `\DEVICE\HARDDISKVOLUME<n>` form, and the file does not record `n`.
/// Volume numbers 1 to [`MAX_VOLUME_NUMBER`] are tried: a 32-bit hash match is the evidence,
/// and the number tried is not reported.
pub fn path_has_hash(version: u32, path: &str, hash: u32) -> bool {
    if scca_hash(version, path) == hash {
        return true;
    }
    let Some(rest) = path.strip_prefix(r"\VOLUME{") else {
        return false;
    };
    let Some((_, rest)) = rest.split_once('}') else {
        return false;
    };
    (1..=MAX_VOLUME_NUMBER)
        .any(|n| scca_hash(version, &format!(r"\DEVICE\HARDDISKVOLUME{n}{rest}")) == hash)
}

/// Highest `\DEVICE\HARDDISKVOLUME<n>` tried for a `\VOLUME{...}` path.
pub const MAX_VOLUME_NUMBER: u32 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xp_hash_matches_the_documented_example() {
        // libscca's documentation: NOTEPAD.EXE on Windows XP.
        assert_eq!(
            scca_xp_hash(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\NOTEPAD.EXE"),
            0x189578da
        );
    }

    #[test]
    fn xp_hash_matches_a_real_file_name() {
        // artifacts/17: CMD.EXE-087B4001.pf
        assert_eq!(
            scca_hash(17, r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE"),
            0x087B4001
        );
    }

    #[test]
    fn vista_hash_matches_real_file_names() {
        // forensic-testenv prefetch-v23-vista-cmd: CMD.EXE-89305D47.pf (Vista)
        assert_eq!(
            scca_hash(23, r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE"),
            0x89305D47
        );
        // artifacts/23: NOTEPAD.EXE-D8414F97.pf
        assert_eq!(
            scca_hash(23, r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NOTEPAD.EXE"),
            0xD8414F97
        );
    }

    #[test]
    fn a_volume_guid_path_is_hashed_as_its_device_path() {
        // artifacts/30: CMD.EXE-D269B812.pf
        let path = r"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\SYSTEM32\CMD.EXE";
        assert!(path_has_hash(30, path, 0xD269B812));
        assert!(!path_has_hash(30, path, 0xD269B813));
        assert!(!path_has_hash(
            30,
            r"\VOLUME{unterminated\CMD.EXE",
            0xD269B812
        ));
    }
}
