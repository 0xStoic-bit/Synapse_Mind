//! Local text embedding abstraction and `fastembed-rs` backend (`bge-small-en-v1.5`).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::{CoreError, Result};

/// Fixed embedding dimension for `BAAI/bge-small-en-v1.5`.
pub const EMBEDDING_DIM: usize = 384;

/// Resolves a user-scoped cache directory outside the repository for downloaded ONNX models.
///
/// Honors a non-empty `FASTEMBED_CACHE_DIR` override; otherwise places model files under
/// `%LOCALAPPDATA%\synapse-mind\fastembed_cache` on Windows, `$XDG_CACHE_HOME/synapse-mind/fastembed_cache`
/// or `$HOME/.cache/synapse-mind/fastembed_cache` on Unix, and `std::env::temp_dir()/synapse-mind/fastembed_cache`
/// as a last resort. (`fastembed` itself also honors `HF_HOME` if set.)
pub fn default_model_cache_dir() -> PathBuf {
    default_model_cache_dir_from(
        std::env::var_os("FASTEMBED_CACHE_DIR"),
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("USERPROFILE"),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("HOME"),
        std::env::temp_dir(),
    )
}

fn non_empty_os(val: Option<OsString>) -> Option<PathBuf> {
    val.filter(|s| !s.is_empty()).map(PathBuf::from)
}

fn default_model_cache_dir_from(
    fastembed_cache_dir: Option<OsString>,
    local_app_data: Option<OsString>,
    user_profile: Option<OsString>,
    xdg_cache_home: Option<OsString>,
    home: Option<OsString>,
    temp_dir: PathBuf,
) -> PathBuf {
    if let Some(explicit) = non_empty_os(fastembed_cache_dir) {
        return explicit;
    }

    #[cfg(windows)]
    {
        let _ = (&xdg_cache_home, &home);
        if let Some(local) = non_empty_os(local_app_data) {
            return local.join("synapse-mind").join("fastembed_cache");
        }
        if let Some(profile) = non_empty_os(user_profile) {
            return profile
                .join("AppData")
                .join("Local")
                .join("synapse-mind")
                .join("fastembed_cache");
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (&local_app_data, &user_profile);
        if let Some(xdg) = non_empty_os(xdg_cache_home) {
            return xdg.join("synapse-mind").join("fastembed_cache");
        }
        if let Some(home_dir) = non_empty_os(home) {
            return home_dir
                .join(".cache")
                .join("synapse-mind")
                .join("fastembed_cache");
        }
    }

    temp_dir.join("synapse-mind").join("fastembed_cache")
}

/// Produces fixed-dimensional dense text embeddings (`EMBEDDING_DIM` = 384).
pub trait Embedder: Send + Sync {
    /// Output vector dimensionality.
    fn dimension(&self) -> usize {
        EMBEDDING_DIM
    }

    /// Generates one dense embedding vector per input string in order.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;

    /// Convenience helper for embedding a single text input.
    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        let mut vectors = self.embed_batch(&[text])?;
        if vectors.len() != 1 {
            return Err(CoreError::EmbeddingCountMismatch {
                expected: 1,
                actual: vectors.len(),
            });
        }
        vectors.pop().ok_or(CoreError::EmbeddingCountMismatch {
            expected: 1,
            actual: 0,
        })
    }
}

impl<T: Embedder + ?Sized> Embedder for Arc<T> {
    fn dimension(&self) -> usize {
        (**self).dimension()
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        (**self).embed_batch(texts)
    }
}

impl<T: Embedder + ?Sized> Embedder for Box<T> {
    fn dimension(&self) -> usize {
        (**self).dimension()
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        (**self).embed_batch(texts)
    }
}

/// Validates dimensionality, finiteness, and non-zero L2 norm before cosine indexing.
pub(crate) fn validate_embedding(vec: &[f32], expected_dim: usize) -> Result<()> {
    if vec.len() != expected_dim {
        return Err(CoreError::InvalidEmbeddingDim {
            expected: expected_dim,
            actual: vec.len(),
        });
    }
    let mut norm_sq = 0.0_f64;
    for &val in vec {
        if !val.is_finite() {
            return Err(CoreError::InvalidEmbeddingVector(
                "embedding contains NaN or infinite component",
            ));
        }
        let v = f64::from(val);
        norm_sq += v * v;
    }
    if norm_sq <= 0.0 {
        return Err(CoreError::InvalidEmbeddingVector(
            "embedding must have non-zero norm for cosine distance",
        ));
    }
    Ok(())
}

/// Encodes `f32` embedding components as little-endian bytes for `sqlite-vec`.
pub(crate) fn f32_slice_to_le_bytes(vec: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(vec));
    for &val in vec {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// `fastembed-rs` implementation backed by `BAAI/bge-small-en-v1.5` (ONNX Runtime).
#[cfg(feature = "fastembed")]
pub mod fastembed_impl {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};

    use super::{EMBEDDING_DIM, Embedder, validate_embedding};
    use crate::{CoreError, Result};

    /// Local CPU embedder powered by `fastembed::TextEmbedding` (`BGESmallENV15`).
    pub struct FastEmbedder {
        model: Mutex<TextEmbedding>,
    }

    impl FastEmbedder {
        /// Returns the user-level model cache directory used by [`FastEmbedder::try_new_default`]
        /// (always outside the repository unless `FASTEMBED_CACHE_DIR` / `HF_HOME` points inside).
        pub fn default_cache_dir() -> PathBuf {
            super::default_model_cache_dir()
        }

        /// Initializes `BAAI/bge-small-en-v1.5` using [`FastEmbedder::default_cache_dir`].
        pub fn try_new_default() -> Result<Self> {
            Self::try_new_with_cache(Self::default_cache_dir())
        }

        /// Initializes `BAAI/bge-small-en-v1.5` with an explicit local model cache directory.
        pub fn try_new_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            Self::try_new_model_with_cache(EmbeddingModel::BGESmallENV15, cache_dir)
        }

        /// Initializes a specific `fastembed::EmbeddingModel` using an explicit local cache directory.
        pub fn try_new_model_with_cache(
            model: EmbeddingModel,
            cache_dir: impl Into<PathBuf>,
        ) -> Result<Self> {
            let cache_dir = cache_dir.into();
            std::fs::create_dir_all(&cache_dir).map_err(|e| {
                CoreError::Embedder(format!(
                    "failed to create fastembed cache directory `{}`: {e}",
                    cache_dir.display()
                ))
            })?;
            let options = TextInitOptions::new(model)
                .with_cache_dir(cache_dir)
                .with_show_download_progress(false);
            Self::try_new(options)
        }

        /// Initializes `FastEmbedder` from custom `fastembed::TextInitOptions`.
        pub fn try_new(options: TextInitOptions) -> Result<Self> {
            let model =
                TextEmbedding::try_new(options).map_err(|e| CoreError::Embedder(e.to_string()))?;
            Ok(Self {
                model: Mutex::new(model),
            })
        }
    }

    impl Embedder for FastEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            if texts.is_empty() {
                return Ok(Vec::new());
            }
            let mut guard = self
                .model
                .lock()
                .map_err(|_| CoreError::Embedder("fastembed mutex poisoned".to_owned()))?;
            let vectors = guard
                .embed(texts, None)
                .map_err(|e| CoreError::Embedder(e.to_string()))?;
            if vectors.len() != texts.len() {
                return Err(CoreError::EmbeddingCountMismatch {
                    expected: texts.len(),
                    actual: vectors.len(),
                });
            }
            for vec in &vectors {
                validate_embedding(vec, EMBEDDING_DIM)?;
            }
            Ok(vectors)
        }
    }

    /// Dual `fastembed-rs` embedder routing single queries (`embed_one`) to FP32
    /// (`BGESmallENV15`) and batch indexing (`embed_batch`) to INT8 (`BGESmallENV15Q`).
    ///
    /// Both models emit 384-dimensional cosine-compatible vectors in the same embedding space.
    pub struct DualEmbedder {
        query: FastEmbedder,
        batch: FastEmbedder,
    }

    impl DualEmbedder {
        /// Returns the user-level model cache directory used by [`DualEmbedder::try_new_default`].
        pub fn default_cache_dir() -> PathBuf {
            super::default_model_cache_dir()
        }

        /// Initializes FP32 `BGESmallENV15` (queries) and INT8 `BGESmallENV15Q` (batches)
        /// using [`DualEmbedder::default_cache_dir`].
        pub fn try_new_default() -> Result<Self> {
            Self::try_new_with_cache(Self::default_cache_dir())
        }

        /// Initializes both models using an explicit local model cache directory.
        pub fn try_new_with_cache(cache_dir: impl Into<PathBuf>) -> Result<Self> {
            let cache_dir = cache_dir.into();
            let query = FastEmbedder::try_new_model_with_cache(
                EmbeddingModel::BGESmallENV15,
                cache_dir.clone(),
            )?;
            let batch =
                FastEmbedder::try_new_model_with_cache(EmbeddingModel::BGESmallENV15Q, cache_dir)?;
            Ok(Self { query, batch })
        }

        /// Initializes `DualEmbedder` from explicit query (FP32) and batch (INT8) options.
        pub fn try_new(
            query_options: TextInitOptions,
            batch_options: TextInitOptions,
        ) -> Result<Self> {
            let query = FastEmbedder::try_new(query_options)?;
            let batch = FastEmbedder::try_new(batch_options)?;
            Ok(Self { query, batch })
        }

        /// Returns a reference to the single-query FP32 embedder (`BGESmallENV15`).
        pub fn query_embedder(&self) -> &FastEmbedder {
            &self.query
        }

        /// Returns a reference to the batch-indexing INT8 embedder (`BGESmallENV15Q`).
        pub fn batch_embedder(&self) -> &FastEmbedder {
            &self.batch
        }
    }

    impl Embedder for DualEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.batch.embed_batch(texts)
        }

        fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
            self.query.embed_one(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_model_cache_dir_resolves_outside_repository() {
        let dir = default_model_cache_dir();
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = crate_dir
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        assert!(
            dir.is_absolute(),
            "cache dir must be absolute, got: {}",
            dir.display()
        );
        assert!(
            !dir.starts_with(repo_root),
            "cache dir `{}` must be outside repository `{}`",
            dir.display(),
            repo_root.display()
        );
    }

    #[test]
    fn default_model_cache_dir_precedence_and_fallbacks() {
        let temp = PathBuf::from("/tmp/fallback");
        let explicit = default_model_cache_dir_from(
            Some(OsString::from("D:\\models\\fe")),
            Some(OsString::from("C:\\Users\\u\\AppData\\Local")),
            None,
            None,
            None,
            temp.clone(),
        );
        assert_eq!(explicit, PathBuf::from("D:\\models\\fe"));

        let empty_override_falls_back = default_model_cache_dir_from(
            Some(OsString::from("")),
            Some(OsString::from("C:\\Users\\u\\AppData\\Local")),
            Some(OsString::from("C:\\Users\\u")),
            Some(OsString::from("/xdg/cache")),
            Some(OsString::from("/home/u")),
            temp.clone(),
        );
        #[cfg(windows)]
        assert_eq!(
            empty_override_falls_back,
            PathBuf::from("C:\\Users\\u\\AppData\\Local")
                .join("synapse-mind")
                .join("fastembed_cache")
        );
        #[cfg(not(windows))]
        assert_eq!(
            empty_override_falls_back,
            PathBuf::from("/xdg/cache")
                .join("synapse-mind")
                .join("fastembed_cache")
        );

        let temp_fallback = default_model_cache_dir_from(None, None, None, None, None, temp);
        assert_eq!(
            temp_fallback,
            PathBuf::from("/tmp/fallback")
                .join("synapse-mind")
                .join("fastembed_cache")
        );
    }
}
