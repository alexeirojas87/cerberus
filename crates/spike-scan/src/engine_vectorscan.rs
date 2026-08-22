#[cfg(feature = "vectorscan")]
mod imp {
    use std::time::Duration;

    use vectorscan::compile::{BlockDatabase, Pattern, PatternFlag};
    use vectorscan::scratch::Scratch;

    pub(crate) struct VectorscanEngine {
        db: BlockDatabase,
        scratch: Scratch,
        compile_time: Duration,
    }

    impl VectorscanEngine {
        pub(crate) fn new(patterns: &[String]) -> Result<Self, String> {
            let compile_start = std::time::Instant::now();

            let compiled: Vec<Pattern> = patterns
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    Pattern::new(p, i as u32, PatternFlag::CASELESS | PatternFlag::SOM_LEFTMOST)
                        .map_err(|e| format!("Vectorscan pattern {} compile error: {e}", i))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let db = BlockDatabase::compile(&compiled).map_err(|e| format!("Vectorscan DB compile error: {e}"))?;

            let scratch = db
                .alloc_scratch()
                .map_err(|e| format!("Vectorscan scratch alloc error: {e}"))?;

            let compile_time = compile_start.elapsed();

            Ok(Self {
                db,
                scratch,
                compile_time,
            })
        }

        pub(crate) fn scan(&self, payload: &str) -> Result<(Duration, usize), String> {
            let start = std::time::Instant::now();
            let mut count: usize = 0;

            self.db
                .scan(payload, &self.scratch, |_id: u32| {
                    count += 1;
                    vectorscan::scan::ScanControl::Continue
                })
                .map_err(|e| format!("Vectorscan scan error: {e}"))?;

            let elapsed = start.elapsed();
            Ok((elapsed, count))
        }

        pub(crate) fn compile_time(&self) -> Duration {
            self.compile_time
        }
    }
}

#[cfg(feature = "vectorscan")]
pub(crate) use imp::VectorscanEngine;

#[cfg(not(feature = "vectorscan"))]
mod imp {
    pub(crate) struct VectorscanEngine;

    impl VectorscanEngine {
        #[allow(clippy::unnecessary_wraps)]
        pub(crate) fn new(_patterns: &[String]) -> Result<Self, String> {
            Err("Vectorscan feature not enabled (compile with --features vectorscan)".to_string())
        }

        #[allow(clippy::unnecessary_wraps)]
        pub(crate) fn scan(&self, _payload: &str) -> Result<(std::time::Duration, usize), String> {
            Err("Vectorscan feature not enabled".to_string())
        }

        pub(crate) fn compile_time(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
    }
}

#[cfg(not(feature = "vectorscan"))]
pub(crate) use imp::VectorscanEngine;
