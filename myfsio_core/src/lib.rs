mod crypto;
mod hashing;
mod metadata;
mod sigv4;
mod storage;
mod streaming;
mod validation;

use pyo3::prelude::*;

#[pymodule]
mod myfsio_core {
    use super::*;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(sigv4::verify_sigv4_signature, m)?)?;
        m.add_function(wrap_pyfunction!(sigv4::derive_signing_key, m)?)?;
        m.add_function(wrap_pyfunction!(sigv4::compute_signature, m)?)?;
        m.add_function(wrap_pyfunction!(sigv4::build_string_to_sign, m)?)?;
        m.add_function(wrap_pyfunction!(sigv4::constant_time_compare, m)?)?;
        m.add_function(wrap_pyfunction!(sigv4::clear_signing_key_cache, m)?)?;

        m.add_function(wrap_pyfunction!(hashing::md5_file, m)?)?;
        m.add_function(wrap_pyfunction!(hashing::md5_bytes, m)?)?;
        m.add_function(wrap_pyfunction!(hashing::sha256_file, m)?)?;
        m.add_function(wrap_pyfunction!(hashing::sha256_bytes, m)?)?;
        m.add_function(wrap_pyfunction!(hashing::md5_sha256_file, m)?)?;

        m.add_function(wrap_pyfunction!(validation::validate_object_key, m)?)?;
        m.add_function(wrap_pyfunction!(validation::validate_bucket_name, m)?)?;

        m.add_function(wrap_pyfunction!(metadata::read_index_entry, m)?)?;

        m.add_function(wrap_pyfunction!(storage::write_index_entry, m)?)?;
        m.add_function(wrap_pyfunction!(storage::delete_index_entry, m)?)?;
        m.add_function(wrap_pyfunction!(storage::check_bucket_contents, m)?)?;
        m.add_function(wrap_pyfunction!(storage::shallow_scan, m)?)?;
        m.add_function(wrap_pyfunction!(storage::bucket_stats_scan, m)?)?;
        m.add_function(wrap_pyfunction!(storage::search_objects_scan, m)?)?;
        m.add_function(wrap_pyfunction!(storage::build_object_cache, m)?)?;

        m.add_function(wrap_pyfunction!(streaming::stream_to_file_with_md5, m)?)?;
        m.add_function(wrap_pyfunction!(streaming::assemble_parts_with_md5, m)?)?;

        m.add_function(wrap_pyfunction!(crypto::encrypt_stream_chunked, m)?)?;
        m.add_function(wrap_pyfunction!(crypto::decrypt_stream_chunked, m)?)?;

        Ok(())
    }
}
