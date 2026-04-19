use crate::error::StorageError;
use myfsio_common::types::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::io::AsyncRead;

pub type StorageResult<T> = Result<T, StorageError>;
pub type AsyncReadStream = Pin<Box<dyn AsyncRead + Send>>;

#[allow(async_fn_in_trait)]
pub trait StorageEngine: Send + Sync {
    async fn list_buckets(&self) -> StorageResult<Vec<BucketMeta>>;
    async fn create_bucket(&self, name: &str) -> StorageResult<()>;
    async fn delete_bucket(&self, name: &str) -> StorageResult<()>;
    async fn bucket_exists(&self, name: &str) -> StorageResult<bool>;
    async fn bucket_stats(&self, name: &str) -> StorageResult<BucketStats>;

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        stream: AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta>;

    async fn get_object(&self, bucket: &str, key: &str) -> StorageResult<(ObjectMeta, AsyncReadStream)>;

    async fn get_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf>;

    async fn head_object(&self, bucket: &str, key: &str) -> StorageResult<ObjectMeta>;

    async fn delete_object(&self, bucket: &str, key: &str) -> StorageResult<()>;

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> StorageResult<ObjectMeta>;

    async fn get_object_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<HashMap<String, String>>;

    async fn put_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()>;

    async fn list_objects(&self, bucket: &str, params: &ListParams) -> StorageResult<ListObjectsResult>;

    async fn list_objects_shallow(
        &self,
        bucket: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult>;

    async fn initiate_multipart(
        &self,
        bucket: &str,
        key: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<String>;

    async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        stream: AsyncReadStream,
    ) -> StorageResult<String>;

    async fn upload_part_copy(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        src_bucket: &str,
        src_key: &str,
        range: Option<(u64, u64)>,
    ) -> StorageResult<(String, chrono::DateTime<chrono::Utc>)>;

    async fn complete_multipart(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[PartInfo],
    ) -> StorageResult<ObjectMeta>;

    async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> StorageResult<()>;

    async fn list_parts(&self, bucket: &str, upload_id: &str) -> StorageResult<Vec<PartMeta>>;

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> StorageResult<Vec<MultipartUploadInfo>>;

    async fn get_bucket_config(&self, bucket: &str) -> StorageResult<BucketConfig>;
    async fn set_bucket_config(&self, bucket: &str, config: &BucketConfig) -> StorageResult<()>;

    async fn is_versioning_enabled(&self, bucket: &str) -> StorageResult<bool>;
    async fn set_versioning(&self, bucket: &str, enabled: bool) -> StorageResult<()>;

    async fn list_object_versions(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Vec<VersionInfo>>;

    async fn get_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Vec<Tag>>;

    async fn set_object_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: &[Tag],
    ) -> StorageResult<()>;

    async fn delete_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<()>;
}
