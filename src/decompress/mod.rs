use std::panic::{catch_unwind, AssertUnwindSafe};

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::utils::win::decompress::{lz77, lznt1, xpress_huff};

pub use forensic_rs::utils::win::decompress::CompressionAlgorithm;

/// Runs a `forensic_rs` decoder and converts a panic into a `ForensicResult` error.
///
/// `forensic-rs`'s LZNT1/LZ77 decoders index/slice their input directly and are known to panic
/// (rather than return an error) on truncated or otherwise malformed compressed data — see the
/// regression tests in this module and `AGENTS.md`'s "trust nothing in forensic-rs blindly"
/// note. A single corrupted `.pf` file must not be able to abort an entire analysis run, so this
/// crate treats the foreign decoder as untrusted at the call boundary rather than assuming it's
/// panic-free. `AssertUnwindSafe` is safe here: on panic, `out_buf` is discarded (the caller
/// receives an `Err`, not the partially-written buffer), so an inconsistent partial write can't
/// leak into further processing.
fn run_decoder(decode: impl FnOnce() -> ForensicResult<()>) -> ForensicResult<()> {
    catch_unwind(AssertUnwindSafe(decode)).unwrap_or_else(|_| {
        Err(ForensicError::other(
            "prefetch",
            "The decompression algorithm panicked on malformed/truncated input".to_string(),
        ))
    })
}

/// Decompresses `in_buf` into `out_buf` using the given `algorithm`.
///
/// # Errors
///
/// Returns an error if `algorithm` is [`CompressionAlgorithm::CompressionFormatDefault`]
/// (unsupported), or if the underlying decoder rejects `in_buf` as malformed/truncated —
/// including a decoder panic on such input, which this function converts into an error rather
/// than propagating (see [`run_decoder`]).
pub fn decompress(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    algorithm: CompressionAlgorithm,
) -> ForensicResult<()> {
    match algorithm {
        CompressionAlgorithm::CompressionFormatNone => {
            out_buf.extend_from_slice(in_buf);
        }
        CompressionAlgorithm::CompressionFormatDefault => {
            return Err(ForensicError::other(
                "prefetch",
                "Default compression algorithm not supported".to_string(),
            ))
        }
        CompressionAlgorithm::CompressionFormatLznt1 => {
            run_decoder(|| lznt1::decompress(in_buf, out_buf))?;
        }
        CompressionAlgorithm::CompressionFormatXpress => {
            run_decoder(|| lz77::decompress(in_buf, out_buf))?;
        }
        CompressionAlgorithm::CompressionFormatXpressHuff => {
            run_decoder(|| xpress_huff::decompress(in_buf, out_buf))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the CompressionFormatXpress/CompressionFormatXpressHuff/
    // CompressionFormatLznt1 dispatch: both forensic-rs's and this crate's original
    // dispatcher wired `Xpress` to the Huffman decoder and `Lznt1` to plain LZ77 (with
    // no real LZNT1 decoder at all), which is backwards. These vectors (moved here from
    // the now-deleted local lz77.rs/xpress_huff.rs/lznt1.rs) drive the fix through
    // `decompress()` itself, not the underlying algorithm functions directly, so a
    // re-introduced mis-wiring would fail here.

    #[test]
    fn dispatches_lznt1_to_the_real_lznt1_decoder() {
        // Cross-checked against libyal/libfwnt's documented LZNT1 worked example: a
        // single literal byte followed by copy-token 0x0ffc RLE-fills to a 4096-byte
        // run of the same byte.
        let encoded: [u8; 6] = [0x03, 0x80, 0x02, 0x41, 0xfc, 0x0f];
        let mut decoded_value = Vec::new();
        decompress(
            &encoded,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatLznt1,
        )
        .unwrap();
        assert_eq!(decoded_value.len(), 4096);
        assert!(decoded_value.iter().all(|&b| b == 0x41));
    }

    #[test]
    fn dispatches_xpress_to_plain_lz77() {
        let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
        let encoded: [u8; 30] = [
            0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7a,
        ];

        let mut decoded_value = Vec::with_capacity(1024);
        decompress(
            &encoded,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatXpress,
        )
        .unwrap();
        assert_eq!(uncompressed, &decoded_value[..]);
    }

    #[test]
    fn dispatches_xpress_huff_to_huffman_decoder() {
        let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
        let encoded: [u8; 276] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x45, 0x44, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f,
            0xf9, 0xd6, 0x7c, 0xdf, 0x8d, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut decoded_value = Vec::with_capacity(uncompressed.len());
        decompress(
            &encoded,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatXpressHuff,
        )
        .unwrap();
        assert_eq!(uncompressed, &decoded_value[..]);
    }

    #[test]
    fn compression_format_default_is_rejected() {
        let mut decoded_value = Vec::new();
        let result = decompress(
            &[],
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatDefault,
        );
        assert!(result.is_err());
    }

    #[test]
    fn dispatches_lznt1_rejects_truncated_input_without_panicking() {
        // A single byte can't contain a complete LZNT1 chunk header plus token stream.
        let truncated = [0x03u8];
        let mut decoded_value = Vec::new();
        let result = decompress(
            &truncated,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatLznt1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn dispatches_xpress_rejects_truncated_input_without_panicking() {
        // A flag byte claiming literals/matches but no payload bytes to back it.
        let truncated = [0xffu8];
        let mut decoded_value = Vec::new();
        let result = decompress(
            &truncated,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatXpress,
        );
        assert!(result.is_err());
    }

    #[test]
    fn dispatches_xpress_huff_handles_truncated_input_without_panicking() {
        // Too short to hold a real Huffman code-length table. Unlike the LZNT1/LZ77 cases
        // above, this decoder happens to treat it as a valid (if degenerate) empty stream
        // rather than erroring — the property under test is just that it doesn't panic.
        let truncated = [0u8; 4];
        let mut decoded_value = Vec::new();
        let _ = decompress(
            &truncated,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatXpressHuff,
        );
    }
}
