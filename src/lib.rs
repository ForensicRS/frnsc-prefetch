pub mod anomaly;
pub mod common;
pub mod decompress;
pub mod metrics;
pub mod parser;
pub mod prefetch;
pub mod trace;
pub mod volume;

#[cfg(test)]
pub(crate) mod tst;

pub mod prelude {
    pub use crate::anomaly::PrefetchAnomaly;
    pub use crate::common::PrefetchFile;
    pub use crate::parser::PrefetchParserFactory;
    pub use crate::prefetch::{
        read_prefetch_file, read_prefetch_file_compressed, read_prefetch_file_no_compressed,
        read_prefetch_form_fs,
    };
}
