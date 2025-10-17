#[global_allocator]
pub static GLOBAL_ALLOCATOR: &alloc_cat::AllocCat = &alloc_cat::ALLOCATOR;

use wasm_bindgen::prelude::*;

const DEFAULT_SEED: u64 = 0;
const DEFAULT_SECRET_SIZE: usize = 192;

/// Computes XXHash32 (32-bit) hash
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `seed` - Seed value for hash (default: 0)
#[wasm_bindgen]
pub fn xxh32(input: &[u8], seed: Option<u32>) -> u32 {
    xxhash_rust::xxh32::xxh32(input, seed.unwrap_or(DEFAULT_SEED as u32))
}

/// Computes XXHash64 (64-bit) hash
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `seed` - Seed value for hash (default: 0)
#[wasm_bindgen]
pub fn xxh64(input: &[u8], seed: Option<u64>) -> u64 {
    xxhash_rust::xxh64::xxh64(input, seed.unwrap_or(DEFAULT_SEED))
}

/// Computes XXH3 64-bit hash using XXH3
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `seed` - Seed value for hash (default: 0)
#[wasm_bindgen]
pub fn xxh3_64(input: &[u8], seed: Option<u64>) -> u64 {
    match seed {
        Some(x) => xxhash_rust::xxh3::xxh3_64_with_seed(input, x),
        None => xxhash_rust::xxh3::xxh3_64(input),
    }
}

/// Computes XXH3 64-bit hash using XXH3 (with Secret)
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `secret` - Secret value
#[wasm_bindgen]
pub fn xxh3_64_with_secret(input: &[u8], secret: &[u8]) -> Result<u64, JsValue> {
    let secret_bytes: [u8; DEFAULT_SECRET_SIZE] = secret.try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "Invalid secret length, default '{}'",
            DEFAULT_SECRET_SIZE
        ))
    })?;

    Ok(xxhash_rust::xxh3::xxh3_64_with_secret(input, &secret_bytes))
}

/// Computes XXHash128 (128-bit) hash using XXH3
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `seed` - Seed value for hash (default: 0)
#[wasm_bindgen]
pub fn xxh3_128(input: &[u8], seed: Option<u64>) -> u128 {
    match seed {
        Some(x) => xxhash_rust::xxh3::xxh3_128_with_seed(input, x),
        None => xxhash_rust::xxh3::xxh3_128(input),
    }
}

/// Computes XXHash128 (128-bit) hash using XXH3 (with Secret)
///
/// # Arguments
///
/// * `input` - Input data to hash
/// * `secret` - Secret value
#[wasm_bindgen]
pub fn xxh3_128_with_secret(input: &[u8], secret: &[u8]) -> Result<u128, JsValue> {
    let secret_bytes: [u8; DEFAULT_SECRET_SIZE] = secret.try_into().map_err(|_| {
        JsValue::from_str(&format!(
            "Invalid secret length, default '{}'",
            DEFAULT_SECRET_SIZE
        ))
    })?;

    Ok(xxhash_rust::xxh3::xxh3_128_with_secret(
        input,
        &secret_bytes,
    ))
}

/// Streaming XXHash32 calculator
#[wasm_bindgen]
pub struct XxHash32 {
    h: xxhash_rust::xxh32::Xxh32,
    s: u32,
}

#[wasm_bindgen]
impl XxHash32 {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: Option<u32>) -> Self {
        let seed_value = seed.unwrap_or(DEFAULT_SEED as u32);
        XxHash32 {
            h: xxhash_rust::xxh32::Xxh32::new(seed_value),
            s: seed_value,
        }
    }

    /// Updates the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        self.h.update(data);
    }

    /// Finalizes the hash and returns the result
    pub fn digest(&self) -> u32 {
        self.h.digest()
    }

    /// Resets the hasher with optional new seed
    pub fn reset(&mut self) {
        self.h.reset(self.s);
    }
}

use xxhash_rust::{xxh3::Xxh3Builder, xxh64::Xxh64Builder};

/// Streaming XxHash64 calculator
#[wasm_bindgen]
pub struct XxHash64 {
    h: xxhash_rust::xxh64::Xxh64,
    s: u64,
}

#[wasm_bindgen]
impl XxHash64 {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: Option<u64>) -> Self {
        let seed_value = seed.unwrap_or(DEFAULT_SEED);
        XxHash64 {
            h: Xxh64Builder::new(seed_value).build(),
            s: seed_value,
        }
    }

    /// Updates the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        self.h.update(data);
    }

    /// Finalizes the hash and returns the result
    pub fn digest(&self) -> u64 {
        self.h.digest()
    }

    /// Resets the hasher with optional new seed
    pub fn reset(&mut self) {
        self.h.reset(self.s);
    }
}

/// Streaming XxHash64 calculator
#[wasm_bindgen]
pub struct XxHash3 {
    h: xxhash_rust::xxh3::Xxh3,
}

#[wasm_bindgen]
impl XxHash3 {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: Option<u64>, secret: Option<Vec<u8>>) -> Result<Self, JsValue> {
        let builder = Xxh3Builder::new();
        builder.with_seed(seed.unwrap_or(DEFAULT_SEED));
        if let Some(ref secret_bytes) = secret {
            if secret_bytes.len() != DEFAULT_SECRET_SIZE {
                return Err(JsValue::from_str(&format!(
                    "Invalid secret length, default '{}'",
                    DEFAULT_SECRET_SIZE
                )));
            }
        }
        Ok(XxHash3 { h: builder.build() })
    }

    /// Updates the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        self.h.update(data);
    }

    /// Finalizes the hash and returns the result
    pub fn digest(&self) -> u64 {
        self.h.digest()
    }

    /// Finalizes the hash and returns the result
    pub fn digest128(&self) -> u128 {
        self.h.digest128()
    }

    /// Resets the hasher with optional new seed
    pub fn reset(&mut self) {
        self.h.reset();
    }
}

/// Computes multiple hashes for different data chunks in batch
#[wasm_bindgen]
pub fn xxh32_batch(chunks: Vec<js_sys::Uint8Array>, seed: Option<u32>) -> Vec<u32> {
    let mut hasher = XxHash32::new(seed);
    chunks
        .into_iter()
        .map(|chunk| {
            hasher.update(&chunk.to_vec());
            let val = hasher.digest();
            hasher.reset();
            val
        })
        .collect()
}

/// Computes multiple XXHash64 hashes in batch
#[wasm_bindgen]
pub fn xxh64_batch(chunks: Vec<js_sys::Uint8Array>, seed: Option<u64>) -> Vec<u64> {
    let mut hasher = XxHash64::new(seed);
    chunks
        .into_iter()
        .map(|chunk| {
            hasher.update(&chunk.to_vec());
            let val = hasher.digest();
            hasher.reset();
            val
        })
        .collect()
}

/// Computes multiple XXH3 64-bit hashes in batch
#[wasm_bindgen]
pub fn xxh3_64_batch(
    chunks: Vec<js_sys::Uint8Array>,
    seed: Option<u64>,
    secret: Option<Vec<u8>>,
) -> Result<Vec<u64>, JsValue> {
    if let Some(ref secret_bytes) = secret {
        if secret_bytes.len() != DEFAULT_SECRET_SIZE {
            return Err(JsValue::from_str(&format!(
                "Invalid secret length, default '{}'",
                DEFAULT_SECRET_SIZE
            )));
        }
    }
    let mut hasher = XxHash3::new(seed, secret).unwrap();

    let bytes = chunks
        .into_iter()
        .map(|chunk| {
            hasher.update(&chunk.to_vec());
            let val = hasher.digest();
            hasher.reset();
            val
        })
        .collect::<Vec<u64>>();

    Ok(bytes)
}

/// Computes multiple XXH3 128-bit hashes in batch
#[wasm_bindgen]
pub fn xxh3_128_batch(
    chunks: Vec<js_sys::Uint8Array>,
    seed: Option<u64>,
    secret: Option<Vec<u8>>,
) -> Result<Vec<String>, JsValue> {
    if let Some(ref secret_bytes) = secret {
        if secret_bytes.len() != DEFAULT_SECRET_SIZE {
            return Err(JsValue::from_str(&format!(
                "Invalid secret length, default '{}'",
                DEFAULT_SECRET_SIZE
            )));
        }
    }
    let mut hasher = XxHash3::new(seed, secret).unwrap();

    let bytes = chunks
        .into_iter()
        .map(|chunk| {
            hasher.update(&chunk.to_vec());

            let val: u128 = hasher.digest128();

            hasher.reset();

            format!("{:016x}", val)
        })
        .collect::<Vec<String>>();

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use js_sys::Uint8Array;
    use wasm_bindgen_test::wasm_bindgen_test;

    const DEFAULT_DATA: &[u8; 27] = b"http://github.com/ndtao2020";
    const DEFAULT_SECRET: [u8; DEFAULT_SECRET_SIZE] = [
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad,
        0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3,
        0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc,
        0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6,
        0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65,
        0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19,
        0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9,
        0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
        0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb,
        0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb, 0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0,
        0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d,
        0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
        0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    ];

    #[test]
    fn test_hash32() {
        let hash = xxh32(DEFAULT_DATA, None);
        assert_eq!(hash, 3662585684);
    }

    #[test]
    fn test_hash64() {
        let hash = xxh64(DEFAULT_DATA, None);
        assert_eq!(hash, 3958957532803539408);
    }

    #[test]
    fn test_hash3_64() {
        let hash = xxh3_64(DEFAULT_DATA, None);
        assert_eq!(hash, 6566294078340352781);
    }

    #[test]
    fn test_hash3_64_with_secret() {
        let hash = xxh3_64_with_secret(DEFAULT_DATA, &DEFAULT_SECRET).unwrap();
        assert_eq!(hash, 6566294078340352781);
    }

    #[test]
    fn test_hash3_128() {
        let hash = xxh3_128(DEFAULT_DATA, None);
        assert_eq!(hash, 228247660873216781895902422224452457537);
    }

    #[test]
    fn test_hash3_128_with_secret() {
        let hash = xxh3_128_with_secret(DEFAULT_DATA, &DEFAULT_SECRET).unwrap();
        assert_eq!(hash, 228247660873216781895902422224452457537);
    }

    // Helper function to create Uint8Array from slice
    fn create_uint8_array(data: &[u8]) -> Uint8Array {
        Uint8Array::from(data)
    }

    #[wasm_bindgen_test]
    fn test_xxh32_batch_basic() {
        let chunks = vec![
            create_uint8_array(b"hello"),
            create_uint8_array(b"world"),
            create_uint8_array(b"test"),
        ];

        let results = xxh32_batch(chunks, None);

        assert_eq!(results.len(), 3);
        // Verify these are valid XXH32 hashes (non-zero)
        assert!(results[0] != 0);
        assert!(results[1] != 0);
        assert!(results[2] != 0);
        // Verify different inputs produce different hashes
        assert_ne!(results[0], results[1]);
        assert_ne!(results[1], results[2]);
    }
}
