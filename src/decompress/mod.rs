use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::utils::win::decompress::{lz77, lznt1, xpress_huff};

pub use forensic_rs::utils::win::decompress::CompressionAlgorithm;

/// Decompresses `in_buf` into `out_buf` using the given `algorithm`.
///
/// # Errors
///
/// Returns an error if `algorithm` is [`CompressionAlgorithm::CompressionFormatDefault`]
/// (unsupported), or if the underlying decoder rejects `in_buf` as malformed/truncated.
///
/// Xpress-Huffman takes its output size from `out_buf`'s spare capacity, as it always has; the
/// others decode until their input ends. For evidence, use [`decompress_bounded`] with the
/// declared size.
pub fn decompress(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    algorithm: CompressionAlgorithm,
) -> ForensicResult<()> {
    let max_out = match algorithm {
        CompressionAlgorithm::CompressionFormatXpressHuff => {
            out_buf.capacity().saturating_sub(out_buf.len())
        }
        _ => usize::MAX,
    };
    decompress_bounded(in_buf, out_buf, algorithm, max_out)
}

/// [`decompress`], producing at most `max_out` bytes.
///
/// LZNT1 marks its own end, so more output than `max_out` is an error. LZ77 and Xpress-Huffman
/// don't: `max_out` is the size the MAM header declares, and their decoders stop there.
pub fn decompress_bounded(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    algorithm: CompressionAlgorithm,
    max_out: usize,
) -> ForensicResult<()> {
    let start = out_buf.len();
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
            lznt1::decompress_bounded(in_buf, out_buf, max_out)?;
        }
        CompressionAlgorithm::CompressionFormatXpress => {
            lz77::decompress_bounded(in_buf, out_buf, max_out)?;
        }
        CompressionAlgorithm::CompressionFormatXpressHuff => {
            xpress_huff::decompress_bounded(in_buf, out_buf, max_out)?;
        }
    }
    let produced = out_buf.len() - start;
    if produced > max_out {
        return Err(ForensicError::file_size_error(
            "prefetch_file_decompressed",
            max_out as u64,
            produced as u64,
        ));
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
    fn dispatches_xpress_huff_rejects_truncated_input_without_panicking() {
        // Too short to hold a Huffman code-length table.
        let truncated = [0u8; 4];
        let mut decoded_value = Vec::new();
        let result = decompress_bounded(
            &truncated,
            &mut decoded_value,
            CompressionAlgorithm::CompressionFormatXpressHuff,
            1024,
        );
        assert!(result.is_err());
    }
}
