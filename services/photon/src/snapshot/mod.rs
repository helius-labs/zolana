use std::{
    env::temp_dir,
    fs::{self, File, OpenOptions},
    io::{BufReader, Error, Read, Write},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

pub use crate::common::{
    fetch_block_parent_slot, get_network_start_slot, setup_logging, setup_metrics, LoggingFormat,
};
use crate::ingester::{
    fetchers::BlockStreamConfig,
    parser::{
        nullifier_tree_batch_update_parser::has_nullifier_tree_batch_update,
        rings_event_parser::parse_rings_events,
    },
    typedefs::block_info::{BlockInfo, TransactionInfo},
};
use anyhow::{anyhow, Context as AnyhowContext, Result};
use async_stream::stream;
use bincode::{Decode, Encode};
use bytes::{BufMut, Bytes};
use cloud_storage::Client as GcsClient;
use futures::stream::StreamExt;
use futures::{pin_mut, stream, Stream};
use log::{error, info};
use s3::creds::Credentials;
use s3::region::Region;
use s3::{bucket::Bucket, BucketConfiguration};
use s3_utils::multipart_upload::put_object_stream_custom;
use tokio::io::{AsyncRead, ReadBuf};

pub mod gcs_utils;
pub mod s3_utils;

pub const CHUNK_SIZE: usize = 100 * 1024 * 1024;
// Up to 50 MB
pub const TRANSACTIONS_TO_ACCUMULATE: usize = 5000;

const SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Decode, Encode, PartialEq, Eq)]
struct SnapshotHeader {
    version: u8,
    start_slot: u64,
    end_slot: u64,
}

impl SnapshotHeader {
    fn new(start_slot: u64, end_slot: u64) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            start_slot,
            end_slot,
        }
    }

    fn encode(self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::legacy())
            .context("Failed to encode snapshot header")
    }

    fn decode_from_prefix(bytes: &[u8]) -> Result<Option<(Self, usize)>> {
        match bincode::decode_from_slice::<Self, _>(bytes, bincode::config::legacy()) {
            Ok((header, bytes_read)) => {
                header.validate()?;
                Ok(Some((header, bytes_read)))
            }
            Err(bincode::error::DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(err) => Err(anyhow!("Invalid snapshot header: {}", err)),
        }
    }

    fn validate(self) -> Result<()> {
        if self.version != SNAPSHOT_VERSION {
            return Err(anyhow!(
                "Unsupported snapshot version: {}. Please upgrade Photon package",
                self.version
            ));
        }
        Ok(())
    }
}

pub struct R2DirectoryAdapter {
    pub r2_bucket: Bucket,
    pub r2_prefix: String,
}

pub struct R2BucketArgs {
    pub r2_credentials: Credentials,
    pub r2_region: Region,
    pub r2_bucket: String,
    pub create_bucket: bool,
}

pub async fn get_r2_bucket(args: R2BucketArgs) -> Result<Bucket> {
    let bucket = *Bucket::new(
        args.r2_bucket.as_str(),
        args.r2_region.clone(),
        args.r2_credentials.clone(),
    )
    .context("Failed to create R2 bucket client")?
    .with_path_style();
    if args.create_bucket {
        let bucket_exists = bucket
            .exists()
            .await
            .context("Failed to check whether R2 bucket exists")?;
        if !bucket_exists {
            Bucket::create_with_path_style(
                args.r2_bucket.as_str(),
                args.r2_region.clone(),
                args.r2_credentials.clone(),
                BucketConfiguration::default(),
            )
            .await
            .context("Failed to create R2 bucket")?;
        }
    }
    Ok(bucket)
}

struct StreamReader<S> {
    stream: S,
    byte_buffer: Vec<u8>,
}

impl<S> AsyncRead for StreamReader<S>
where
    S: stream::Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.byte_buffer.is_empty() {
            let len = std::cmp::min(self.byte_buffer.len(), buf.remaining_mut());
            buf.put_slice(&self.byte_buffer[..len]);
            self.byte_buffer.drain(..len);
            return Poll::Ready(Ok(()));
        }
        match futures::ready!(self.stream.poll_next_unpin(cx)) {
            Some(Ok(chunk)) => {
                self.byte_buffer.extend_from_slice(chunk.as_ref());
                let len = std::cmp::min(self.byte_buffer.len(), buf.remaining_mut());
                buf.put_slice(&self.byte_buffer[..len]);
                self.byte_buffer.drain(..len);
                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(e)),
            None => Poll::Ready(Ok(())), // EOF
        }
    }
}

impl R2DirectoryAdapter {
    async fn read_file(
        arc_self: Arc<Self>,
        path: String,
    ) -> impl Stream<Item = Result<Bytes>> + std::marker::Send + 'static {
        stream! {
            let r2_directory_adapter = arc_self.clone();
            let mut result = r2_directory_adapter.r2_bucket.get_object_stream(path.clone()).await.with_context(|| format!("Failed to read file: {:?}", path))?;
            let stream = result.bytes();

            while let Some(byte) = stream.next().await {
                let byte = byte.with_context(|| "Failed to read byte from file")?;
                yield Ok(byte);
            }
        }
    }

    async fn list_files(&self) -> Result<Vec<String>> {
        let results = self
            .r2_bucket
            .list(self.r2_prefix.clone(), None)
            .await
            .unwrap_or_default();

        let mut files = Vec::new();
        for result in results {
            for object in result.contents {
                files.push(object.key);
            }
        }
        Ok(files)
    }

    async fn delete_file(&self, path: String) -> Result<()> {
        self.r2_bucket.delete_object(path).await?;
        Ok(())
    }

    async fn write_file(
        &self,
        path: String,
        byte_stream: impl Stream<Item = Result<Bytes>> + std::marker::Send + 'static,
    ) -> Result<()> {
        let path = format!("{}/{}", self.r2_prefix, path);

        pin_mut!(byte_stream);
        // Create a stream that converts `Result<u8, S3Error>` to `Result<Vec<u8>, S3Error>`
        let byte_stream = byte_stream.map(|bytes| bytes.map_err(Error::other));

        let mut stream_reader = StreamReader {
            stream: byte_stream,
            byte_buffer: Vec::new(),
        };
        // Stream the bytes directly to S3 without collecting them in memory
        put_object_stream_custom(&self.r2_bucket, &mut stream_reader, &path).await?;
        Ok(())
    }
}

pub struct GCSDirectoryAdapter {
    pub gcs_client: GcsClient,
    pub gcs_bucket: String,
    pub gcs_prefix: String,
}

impl GCSDirectoryAdapter {
    async fn read_file(
        arc_self: Arc<Self>,
        path: String,
    ) -> impl Stream<Item = Result<Bytes>> + std::marker::Send + 'static {
        stream! {
            let gcs_adapter = arc_self.clone();
            let full_path = if gcs_adapter.gcs_prefix.is_empty() {
                path.clone()
            } else {
                format!("{}/{}", gcs_adapter.gcs_prefix, path)
            };

            let object_data = gcs_adapter.gcs_client
                .object()
                .download(&gcs_adapter.gcs_bucket, &full_path)
                .await
                .with_context(|| format!("Failed to read file from GCS: {:?}", full_path))?;

            // Split the data into chunks to match the streaming behavior
            let mut offset = 0;
            while offset < object_data.len() {
                let end = std::cmp::min(offset + CHUNK_SIZE, object_data.len());
                yield Ok(Bytes::from(object_data[offset..end].to_vec()));
                offset = end;
            }
        }
    }

    async fn list_files(&self) -> Result<Vec<String>> {
        let mut list_request = cloud_storage::ListRequest::default();
        if !self.gcs_prefix.is_empty() {
            list_request.prefix = Some(self.gcs_prefix.clone());
        }

        let objects_stream = self
            .gcs_client
            .object()
            .list(&self.gcs_bucket, list_request)
            .await
            .with_context(|| "Failed to create list stream for GCS")?;

        let prefix_len = if self.gcs_prefix.is_empty() {
            0
        } else {
            self.gcs_prefix.len() + 1
        };
        let mut files = Vec::new();

        pin_mut!(objects_stream);
        while let Some(object_list_result) = objects_stream.next().await {
            let object_list =
                object_list_result.with_context(|| "Failed to list files from GCS")?;
            for object in object_list.items {
                if object.name.len() > prefix_len {
                    files.push(object.name[prefix_len..].to_string());
                }
            }
        }
        Ok(files)
    }

    async fn delete_file(&self, path: String) -> Result<()> {
        let full_path = if self.gcs_prefix.is_empty() {
            path
        } else {
            format!("{}/{}", self.gcs_prefix, path)
        };

        self.gcs_client
            .object()
            .delete(&self.gcs_bucket, &full_path)
            .await
            .with_context(|| format!("Failed to delete file from GCS: {:?}", full_path))?;
        Ok(())
    }

    async fn write_file(
        &self,
        path: String,
        byte_stream: impl Stream<Item = Result<Bytes>> + std::marker::Send + 'static,
    ) -> Result<()> {
        let full_path = if self.gcs_prefix.is_empty() {
            path.clone()
        } else {
            format!("{}/{}", self.gcs_prefix, path)
        };

        // Use resumable upload for reliable large file uploads
        let access_token = gcs_utils::resumable_upload::get_access_token()
            .await
            .with_context(|| "Failed to get GCS access token")?;

        gcs_utils::resumable_upload::resumable_upload(
            &self.gcs_bucket,
            &full_path,
            byte_stream,
            &access_token,
        )
        .await
        .with_context(|| format!("Failed to write file to GCS: {:?}", full_path))?;

        Ok(())
    }
}

pub struct FileSystemDirectoryAdapter {
    pub snapshot_dir: String,
}

impl FileSystemDirectoryAdapter {
    fn read_file(&self, path: String) -> impl Stream<Item = Result<Bytes>> + Send + 'static {
        let path = format!("{}/{}", self.snapshot_dir, path);
        stream! {
            let file = match OpenOptions::new().read(true).open(&path) {
                Ok(file) => file,
                Err(err) => {
                    yield Err(anyhow!(err).context(format!("Failed to open snapshot file {:?}", path)));
                    return;
                }
            };
            let bytes = BufReader::new(file).bytes();
            let mut byte_chunk = vec![];
            for byte in bytes {
                byte_chunk.push(byte.with_context(|| "Failed to read byte from file")?);
                if byte_chunk.len() == CHUNK_SIZE {
                    yield Ok(Bytes::from(std::mem::take(&mut byte_chunk)));
                }
            }
            if !byte_chunk.is_empty() {
                yield Ok(Bytes::from(byte_chunk));
            }
        }
    }

    async fn list_files(&self) -> Result<Vec<String>> {
        if !PathBuf::new().join(&self.snapshot_dir).exists() {
            return Ok(Vec::new());
        }
        let files = fs::read_dir(&self.snapshot_dir)
            .with_context(|| format!("Failed to read directory: {:?}", self.snapshot_dir))?;
        let mut file_names = Vec::new();
        for file in files {
            let file = file?;
            let file_name = file.file_name().into_string().map_err(|file_name| {
                anyhow!("Snapshot file name is not valid UTF-8: {:?}", file_name)
            })?;
            file_names.push(file_name);
        }
        Ok(file_names)
    }

    async fn delete_file(&self, path: String) -> Result<()> {
        let path = format!("{}/{}", self.snapshot_dir, path);
        fs::remove_file(path.clone())
            .with_context(|| format!("Failed to delete file: {:?}", path))?;
        Ok(())
    }

    async fn write_file(
        &self,
        path: String,
        bytes: impl Stream<Item = Result<Bytes>>,
    ) -> Result<()> {
        let (mut temp_file, temp_path) = create_temp_snapshot_file(&self.snapshot_dir)?;
        pin_mut!(bytes);
        while let Some(byte) = bytes.next().await {
            let byte = byte?;
            temp_file
                .write_all(&byte)
                .context("Failed to write snapshot bytes to temp file")?;
        }

        if !PathBuf::new().join(&self.snapshot_dir).exists() {
            fs::create_dir_all(&self.snapshot_dir).with_context(|| {
                format!("Failed to create snapshot directory {}", self.snapshot_dir)
            })?;
        }
        let path = format!("{}/{}", self.snapshot_dir, path);
        fs::rename(temp_path.clone(), path.clone())
            .with_context(|| format!("Failed to rename file: {:?} -> {:?}", temp_path, path))?;
        Ok(())
    }
}

pub enum DirectoryAdapter {
    FileSystem(Arc<FileSystemDirectoryAdapter>),
    R2(Arc<R2DirectoryAdapter>),
    Gcs(Arc<GCSDirectoryAdapter>),
}

impl DirectoryAdapter {
    pub fn from_local_directory(snapshot_dir: String) -> Self {
        Self::FileSystem(Arc::new(FileSystemDirectoryAdapter { snapshot_dir }))
    }

    pub async fn from_r2_bucket_and_prefix_and_env(
        r2_bucket: String,
        r2_prefix: String,
    ) -> Result<Self> {
        let r2_credentials = Credentials::new(
            Some(&std::env::var("R2_ACCESS_KEY").context("R2_ACCESS_KEY is not set")?),
            Some(&std::env::var("R2_SECRET_KEY").context("R2_SECRET_KEY is not set")?),
            None,
            None,
            None,
        )
        .context("Failed to create R2 credentials")?;
        let r2_region = Region::R2 {
            account_id: std::env::var("R2_ACCOUNT_ID").context("R2_ACCOUNT_ID is not set")?,
        };
        let r2_bucket_args = R2BucketArgs {
            r2_credentials,
            r2_region,
            r2_bucket,
            create_bucket: false,
        };
        let r2_bucket = get_r2_bucket(r2_bucket_args).await?;
        Ok(Self::R2(Arc::new(R2DirectoryAdapter {
            r2_bucket,
            r2_prefix,
        })))
    }

    pub async fn from_gcs_bucket_and_prefix_and_env(
        gcs_bucket: String,
        gcs_prefix: String,
    ) -> Result<Self> {
        let gcs_client = GcsClient::default();

        Ok(Self::Gcs(Arc::new(GCSDirectoryAdapter {
            gcs_client,
            gcs_bucket,
            gcs_prefix,
        })))
    }

    async fn read_file(
        &self,
        path: String,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send + 'static>> {
        match self {
            Self::FileSystem(adapter) => Box::pin(adapter.read_file(path)),
            Self::R2(adapter) => {
                Box::pin(R2DirectoryAdapter::read_file(adapter.clone(), path).await)
            }
            Self::Gcs(adapter) => {
                Box::pin(GCSDirectoryAdapter::read_file(adapter.clone(), path).await)
            }
        }
    }

    async fn list_files(&self) -> Result<Vec<String>> {
        match self {
            Self::FileSystem(adapter) => adapter.list_files().await,
            Self::R2(adapter) => adapter.list_files().await,
            Self::Gcs(adapter) => adapter.list_files().await,
        }
    }

    pub async fn delete_file(&self, path: String) -> Result<()> {
        match self {
            Self::FileSystem(adapter) => adapter.delete_file(path).await,
            Self::R2(adapter) => adapter.delete_file(path).await,
            Self::Gcs(adapter) => adapter.delete_file(path).await,
        }
    }

    async fn write_file(
        &self,
        path: String,
        bytes: impl Stream<Item = Result<Bytes>> + std::marker::Send + 'static,
    ) -> Result<()> {
        match self {
            Self::FileSystem(adapter) => adapter.write_file(path, bytes).await,
            Self::R2(adapter) => adapter.write_file(path, bytes).await,
            Self::Gcs(adapter) => adapter.write_file(path, bytes).await,
        }
    }
}

pub fn is_rings_transaction(tx: &TransactionInfo, slot: u64) -> bool {
    match parse_rings_events(tx, slot) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            log::warn!(
                "Skipping transaction {} in snapshot because Rings event parsing failed: {}",
                tx.signature,
                err
            );
            false
        }
    }
}

pub fn is_rings_snapshot_transaction(tx: &TransactionInfo, slot: u64) -> bool {
    is_rings_transaction(tx, slot) || has_nullifier_tree_batch_update(tx)
}

#[derive(Debug)]
pub struct SnapshotFileWithSlots {
    pub file: String,
    pub start_slot: u64,
    pub end_slot: u64,
}

pub async fn get_snapshot_files_with_metadata(
    directory_adapter: &DirectoryAdapter,
) -> anyhow::Result<Vec<SnapshotFileWithSlots>> {
    let snapshot_files = directory_adapter.list_files().await?;
    let mut snapshot_files_with_slots = Vec::new();

    for file in snapshot_files {
        // Make this return an error if file name is not in the expected format
        let parts: Vec<&str> = file.split('-').collect();
        if parts.len() == 3 {
            let start_slot = parts[1].parse::<u64>()?;
            let end_slot = parts[2].parse::<u64>()?;
            snapshot_files_with_slots.push(SnapshotFileWithSlots {
                file,
                start_slot,
                end_slot,
            });
        }
    }
    snapshot_files_with_slots.sort_by_key(|file| file.start_slot);
    Ok(snapshot_files_with_slots)
}

fn create_temp_snapshot_file(dir: &str) -> Result<(File, PathBuf)> {
    let mut temp_dir = temp_dir().join(dir);

    if fs::create_dir_all(&temp_dir).is_err() {
        temp_dir = PathBuf::from(dir).join(".tmp");
        fs::create_dir_all(&temp_dir).context(
            "Failed to create temp directory in both system temp and snapshot directory",
        )?;
    }

    let random_number = rand::random::<u64>();
    let temp_file_path = temp_dir.join(format!("temp-snapshot-{}", random_number));
    if temp_file_path.exists() {
        fs::remove_file(&temp_file_path)
            .with_context(|| format!("Failed to remove existing temp file {:?}", temp_file_path))?;
    }
    info!("Creating temp file: {:?}", temp_file_path);
    let temp_file = File::create(&temp_file_path)
        .with_context(|| format!("Failed to create temp file {:?}", temp_file_path))?;
    Ok((temp_file, temp_file_path))
}

async fn merge_snapshots(directory_adapter: Arc<DirectoryAdapter>) -> Result<()> {
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_SECS: u64 = 5;

    for attempt in 1..=MAX_RETRIES {
        match try_merge_snapshots(directory_adapter.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                error!(
                    "merge_snapshots failed (attempt {}/{}): {:?}",
                    attempt, MAX_RETRIES, e
                );
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }
    Err(anyhow!(
        "merge_snapshots failed after {} attempts",
        MAX_RETRIES
    ))
}

async fn try_merge_snapshots(directory_adapter: Arc<DirectoryAdapter>) -> Result<()> {
    let snapshot_files = get_snapshot_files_with_metadata(directory_adapter.as_ref())
        .await
        .context("Failed to get snapshot files")?;
    let start_slot = snapshot_files
        .first()
        .map(|file| file.start_slot)
        .context("No snapshot files found")?;
    let end_slot = snapshot_files
        .last()
        .map(|file| file.end_slot)
        .context("No snapshot files found")?;
    info!(
        "Merging snapshots from slot {} to slot {}",
        start_slot, end_slot
    );
    let byte_stream = load_byte_stream_from_directory_adapter(directory_adapter.clone()).await;
    create_snapshot_from_byte_stream(byte_stream, directory_adapter.as_ref())
        .await
        .context("Failed to create merged snapshot")?;
    for snapshot_file in snapshot_files {
        directory_adapter
            .delete_file(snapshot_file.file.clone())
            .await
            .with_context(|| format!("Failed to delete snapshot file: {}", snapshot_file.file))?;
    }
    Ok(())
}

pub async fn update_snapshot(
    directory_adapter: Arc<DirectoryAdapter>,
    block_stream_config: BlockStreamConfig,
    full_snapshot_interval_slots: u64,
    incremental_snapshot_interval_slots: u64,
) -> Result<()> {
    // Convert stream to iterator
    let block_stream = block_stream_config.load_block_stream();
    update_snapshot_helper(
        directory_adapter,
        block_stream,
        block_stream_config.last_indexed_slot,
        incremental_snapshot_interval_slots,
        full_snapshot_interval_slots,
    )
    .await?;
    Ok(())
}

pub async fn update_snapshot_helper(
    directory_adapter: Arc<DirectoryAdapter>,
    blocks_stream: impl Stream<Item = Vec<BlockInfo>>,
    last_indexed_slot: u64,
    incremental_snapshot_interval_slots: u64,
    full_snapshot_interval_slots: u64,
) -> Result<()> {
    let snapshot_files = get_snapshot_files_with_metadata(directory_adapter.as_ref())
        .await
        .context("Failed to get snapshot files")?;

    let mut last_full_snapshot_slot = snapshot_files
        .first()
        .map(|file| file.end_slot)
        .unwrap_or(last_indexed_slot);
    let mut last_snapshot_slot = snapshot_files
        .last()
        .map(|file| file.end_slot)
        .unwrap_or(last_indexed_slot);

    let mut byte_buffer = Vec::new();

    pin_mut!(blocks_stream);
    while let Some(blocks) = blocks_stream.next().await {
        for block in blocks {
            let slot = block.metadata.slot;
            let write_full_snapshot = slot
                .saturating_sub(last_full_snapshot_slot)
                .saturating_add(u64::from(last_indexed_slot == 0))
                >= full_snapshot_interval_slots;
            let write_incremental_snapshot = slot
                .saturating_sub(last_snapshot_slot)
                .saturating_add(u64::from(last_snapshot_slot == 0))
                >= incremental_snapshot_interval_slots;

            let trimmed_block = BlockInfo {
                metadata: block.metadata.clone(),
                transactions: block
                    .transactions
                    .iter()
                    .filter(|tx| is_rings_snapshot_transaction(tx, slot))
                    .cloned()
                    .collect(),
            };
            let block_bytes =
                bincode::serde::encode_to_vec(&trimmed_block, bincode::config::legacy())
                    .context("Failed to encode snapshot block")?;
            byte_buffer.extend(block_bytes);

            if write_incremental_snapshot {
                let snapshot_file_path = format!("snapshot-{}-{}", last_snapshot_slot + 1, slot);
                info!("Writing snapshot file: {}", snapshot_file_path);
                let byte_buffer_clone = byte_buffer.clone();
                let byte_stream = stream! {
                    yield Ok(Bytes::from(byte_buffer_clone));
                };
                directory_adapter
                    .as_ref()
                    .write_file(snapshot_file_path, byte_stream)
                    .await
                    .context("Failed to write incremental snapshot")?;
                byte_buffer.clear();
                last_snapshot_slot = slot;
            }
            if write_full_snapshot {
                merge_snapshots(directory_adapter.clone()).await?;
                last_full_snapshot_slot = slot;
            }
        }
    }
    Ok(())
}

async fn read_snapshot_header_from_stream<S>(
    byte_stream: &mut S,
) -> Result<(SnapshotHeader, Vec<u8>)>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    let mut buffered = Vec::new();

    while let Some(bytes) = byte_stream.next().await {
        buffered.extend_from_slice(&bytes?);
        if let Some((header, bytes_read)) = SnapshotHeader::decode_from_prefix(&buffered)? {
            let remaining = buffered.split_off(bytes_read);
            return Ok((header, remaining));
        }
    }

    Err(anyhow!("Snapshot stream ended before header was complete"))
}

#[derive(Default)]
struct SnapshotBlockAccumulator {
    blocks: Vec<BlockInfo>,
    transaction_count: usize,
}

impl SnapshotBlockAccumulator {
    fn push(&mut self, block: BlockInfo) -> Option<Vec<BlockInfo>> {
        self.transaction_count += block.transactions.len();
        self.blocks.push(block);

        if self.transaction_count < TRANSACTIONS_TO_ACCUMULATE {
            return None;
        }

        self.transaction_count = 0;
        Some(std::mem::take(&mut self.blocks))
    }

    fn finish(self) -> Option<Vec<BlockInfo>> {
        if self.blocks.is_empty() {
            None
        } else {
            Some(self.blocks)
        }
    }
}

fn decode_next_snapshot_block(reader: &[u8], index: &mut usize) -> Result<BlockInfo> {
    let (block, size): (BlockInfo, usize) =
        bincode::serde::decode_from_slice(&reader[*index..], bincode::config::legacy())
            .context("Failed to decode snapshot block")?;
    *index += size;
    Ok(block)
}

fn decode_snapshot_blocks(
    reader: &[u8],
    index: &mut usize,
    min_buffered_bytes: usize,
    accumulator: &mut SnapshotBlockAccumulator,
) -> Result<Vec<Vec<BlockInfo>>> {
    let mut ready_blocks = Vec::new();

    while reader.len().saturating_sub(*index) > min_buffered_bytes {
        let block = decode_next_snapshot_block(reader, index)?;
        if let Some(blocks) = accumulator.push(block) {
            ready_blocks.push(blocks);
        }
    }

    Ok(ready_blocks)
}

pub async fn load_byte_stream_from_directory_adapter(
    directory_adapter: Arc<DirectoryAdapter>,
) -> impl Stream<Item = Result<Bytes>> + 'static {
    // Create an asynchronous stream of bytes from the snapshot files
    stream! {
        let snapshot_files =
            get_snapshot_files_with_metadata(directory_adapter.as_ref()).await.context("Failed to retrieve snapshot files")?;
        if snapshot_files.is_empty() {
            yield Err(anyhow!("No snapshot files found"));
            return;
        }

        let start_slot = snapshot_files
            .first()
            .map(|file| file.start_slot)
            .context("No snapshot files found")?;
        let end_slot = snapshot_files
            .last()
            .map(|file| file.end_slot)
            .context("No snapshot files found")?;
        let header = SnapshotHeader::new(start_slot, end_slot);
        yield Ok(Bytes::from(header.encode()?));

        // Iterate over each snapshot file
        for snapshot_file in snapshot_files {
            // Use anyhow context to add more error information
            let byte_stream = directory_adapter.read_file(snapshot_file.file.clone()).await;
            pin_mut!(byte_stream);
            while let Some(byte) = byte_stream.next().await {
                yield byte;
            }
        }
    }
}

pub async fn load_block_stream_from_directory_adapter(
    directory_adapter: Arc<DirectoryAdapter>,
) -> impl Stream<Item = Vec<BlockInfo>> {
    stream! {
        let byte_stream = load_byte_stream_from_directory_adapter(directory_adapter.clone()).await;
        pin_mut!(byte_stream);
        let (_, mut reader) = match read_snapshot_header_from_stream(&mut byte_stream).await {
            Ok(header_and_reader) => header_and_reader,
            Err(err) => {
                error!("Failed to read snapshot header: {}", err);
                return;
            }
        };
        let mut index = 0;
        let mut accumulator = SnapshotBlockAccumulator::default();

        while let Some(bytes) = byte_stream.next().await {
            let bytes = match bytes {
                Ok(bytes) => bytes,
                Err(err) => {
                    error!("Failed to read snapshot bytes: {}", err);
                    return;
                }
            };
            reader.extend(&bytes);
            match decode_snapshot_blocks(&reader, &mut index, CHUNK_SIZE, &mut accumulator) {
                Ok(ready_blocks) => {
                    for blocks in ready_blocks {
                        yield blocks;
                    }
                }
                Err(err) => {
                    error!("Failed to decode snapshot blocks: {}", err);
                    return;
                }
            }
            if index > 0 {
                reader.drain(..index);
                index = 0;
            }
        }

        match decode_snapshot_blocks(&reader, &mut index, 0, &mut accumulator) {
            Ok(ready_blocks) => {
                for blocks in ready_blocks {
                    yield blocks;
                }
            }
            Err(err) => {
                error!("Failed to decode final snapshot blocks: {}", err);
                return;
            }
        }

        if let Some(blocks) = accumulator.finish() {
            yield blocks;
        }
    }
}

pub async fn create_snapshot_from_byte_stream(
    byte_stream: impl Stream<Item = Result<Bytes, anyhow::Error>> + std::marker::Send + 'static,
    directory_adapter: &DirectoryAdapter,
) -> Result<()> {
    let mut byte_stream: Pin<Box<dyn Stream<Item = Result<Bytes, anyhow::Error>> + Send>> =
        Box::pin(byte_stream);
    let (header, byte_buffer) = read_snapshot_header_from_stream(&mut byte_stream).await?;
    let snapshot_name = format!("snapshot-{}-{}", header.start_slot, header.end_slot);
    info!("Creating snapshot: {}", snapshot_name);
    let byte_stream = stream! {
        yield Ok(Bytes::from(byte_buffer));
        while let Some(byte) = byte_stream.next().await {
            yield byte;
        }
    };
    directory_adapter
        .write_file(snapshot_name.clone(), byte_stream)
        .await?;

    info!("Snapshot downloaded successfully to {:?}", snapshot_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_header_codec_round_trips_with_body_prefix() {
        let header = SnapshotHeader::new(10, 20);
        let mut bytes = header.encode().unwrap();
        bytes.extend_from_slice(&[1, 2, 3]);

        let (decoded, bytes_read) = SnapshotHeader::decode_from_prefix(&bytes).unwrap().unwrap();
        assert_eq!(decoded, header);
        assert_eq!(&bytes[bytes_read..], &[1, 2, 3]);
    }

    #[tokio::test]
    async fn reads_snapshot_header_across_stream_chunks() {
        let header = SnapshotHeader::new(30, 40);
        let mut header_bytes = header.encode().unwrap();
        let body_bytes = vec![9, 8, 7];
        let second_chunk = header_bytes.split_off(header_bytes.len() / 2);

        let mut chunks = futures::stream::iter([
            Ok(Bytes::from(header_bytes)),
            Ok(Bytes::from(second_chunk)),
            Ok(Bytes::from(body_bytes.clone())),
        ]);

        let (decoded, remaining) = read_snapshot_header_from_stream(&mut chunks).await.unwrap();
        assert_eq!(decoded, header);
        assert!(remaining.is_empty());

        let body = chunks.next().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), body_bytes.as_slice());
    }
}
