use std::path::{Path, PathBuf};
use std::sync::Arc;

use itertools::Itertools;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use log::{info, warn, error};
use crate::blob_cache::BlobCache;
use crate::metrics;
use crate::types::FileInfo;
use crate::worker::database::Database;
use crate::worker::manager::WorkerState;

pub mod interface;
mod database;
mod database_sqlite;
mod trigrams;
mod encoding;
pub mod journal;
mod manager;


#[derive(Serialize, Deserialize)]
pub struct YaraTask {
    pub id: i64,
    pub yara_rule: String,
    pub files: Vec<FileInfo>,
}

pub async fn main(config: crate::config::WorkerSettings) -> Result<()> {
    // Register prometheus metrics
    metrics::register_metrics();
    metrics::BUILD_INFO.with_label_values(&[env!("CARGO_PKG_VERSION"), "worker"]).set(1.0);

    // Setup the storage
    info!("Connect to file storage");
    let file_storage = crate::storage::connect(config.files.clone()).await?;

    // Get cache
    info!("Setup caches");
    let (file_cache, _file_temp) = match &config.file_cache {
        crate::config::CacheConfig::TempDir { size } => {
            let temp_dir = tempfile::tempdir()?;
            (BlobCache::new(file_storage.clone(), *size, temp_dir.path().to_owned())?, Some(temp_dir))
        }
        crate::config::CacheConfig::Directory { path, size } => {
            (BlobCache::new(file_storage.clone(), *size, PathBuf::from(path))?, None)
        }
    };

    // Figure out where the worker status interface will be hosted
    info!("Determine bind address");
    let bind_address = config.bind_address.clone().unwrap_or("localhost:8080".to_owned());
    let mut addresses = tokio::net::lookup_host(&bind_address).await?.collect_vec();
    let bind_address = match addresses.pop() {
        Some(x) => x,
        None => {
            return Err(anyhow::anyhow!("Couldn't resolve bind address: {}", bind_address));
        }
    };
    info!("Status interface will bind on: {bind_address}");

    info!("Loading classification");
    let ce = config.classification.init()?;

    info!("Setting up database.");
    let database = Database::new_sqlite(config.get_database_directory(), ce).await.context("setting up database")?;

    info!("Spawing processing daemons.");
    let (set_running, running) = tokio::sync::watch::channel(true);
    let data = WorkerState::new(database, file_storage, file_cache, config.clone(), running).await.context("spawning")?;

    // Watch for exit signal
    let exit_notice = Arc::new(tokio::sync::Notify::new());
    tokio::spawn({
        let exit_notice = exit_notice.clone();
        async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    _ = set_running.send(false);
                    exit_notice.notify_waiters();
                },
                Err(err) => {
                    error!("Error waiting for exit signal: {err}");
                },
            }
        }
    });

    // Spawn periodic metrics updater (storage gauges, uptime, filter count)
    let metrics_data = data.clone();
    let metrics_start = std::time::Instant::now();
    tokio::spawn(async move {
        loop {
            // Uptime
            metrics::UPTIME_SECONDS.set(metrics_start.elapsed().as_secs_f64());

            // Storage
            match nix::sys::statvfs::statvfs(&metrics_data.config.data_path) {
                Ok(stats) => {
                    let total = stats.blocks() as f64 * stats.block_size() as f64;
                    let free = stats.blocks_available() as f64 * stats.block_size() as f64;
                    metrics::STORAGE_DISK_TOTAL_BYTES.set(total);
                    metrics::STORAGE_DISK_FREE_BYTES.set(free);
                    if total > 0.0 {
                        metrics::STORAGE_DISK_USED_PERCENT.set((1.0 - free / total) * 100.0);
                    }
                }
                Err(err) => {
                    warn!("Metrics: failed to read disk stats: {err}");
                }
            }

            // Used storage (filter data)
            if let Ok(used) = metrics_data.get_used_storage().await {
                metrics::STORAGE_BYTES_TOTAL.set(used as f64);
            }

            // Filter count
            {
                let filters = metrics_data.filters.read().await;
                metrics::STORAGE_FILTERS_TOTAL.set(filters.len() as i64);
            }

            // Storage pressure
            match metrics_data.check_storage_pressure().await {
                Ok(true) => metrics::STORAGE_PRESSURE.set(1),
                Ok(false) => metrics::STORAGE_PRESSURE.set(0),
                Err(_) => {}
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });

    // Run the worker
    info!("Starting HTTP interface.");
    let api = tokio::spawn(interface::serve(bind_address, config.tls, data.clone(), exit_notice.clone()));
    // let manager = tokio::spawn(worker_manager(data.clone(), recv));

    // Run the worker
    match api.await {
        Ok(Ok(())) => {},
        Ok(Err(err)) => error!("Server crashed: {err}"),
        Err(err) => error!("Server crashed: {err}")
    }

    info!("Waiting for data flush...");
    data.stop().await;

    return Ok(())
}

/// Helper function to remove a file and succeed when missing
pub fn remove_file(path: &Path) -> Result<()> {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err.into());
        }
    };
    return Ok(())
}


fn into_trigrams(bytes: &[u8]) -> Vec<u32> {
    if bytes.len() < 3 {
        return vec![];
    }
    let mut trigrams = vec![];
    let mut trigram: u32 = (bytes[0] as u32) << 8 | (bytes[1] as u32);

    for byte in bytes.iter().skip(2) {
        trigram = (trigram & 0x00FFFF) << 8 | (*byte as u32);
        trigrams.push(trigram);
    }

    return trigrams;
}


/// Calculate the union of two sets of numbers into the the first set
///
/// list need not be ordered
fn union(base: &mut Vec<u64>, other: &Vec<u64>) {
    base.extend(other);
    base.sort_unstable();
    base.dedup();
}

/// Calculate the intersection of two sets of numbers into the the first set
///
/// list must be ordered
fn intersection(base: &mut Vec<u64>, other: &[u64]) {

    let mut base_read_index = 0;
    let mut base_write_index = 0;
    let mut other_index = 0;

    while base_read_index < base.len() && other_index < other.len() {
        match base[base_read_index].cmp(&other[other_index]) {
            std::cmp::Ordering::Less => { base_read_index += 1},
            std::cmp::Ordering::Equal => {
                base[base_write_index] = base[base_read_index];
                base_write_index += 1;
                base_read_index += 1;
                other_index += 1;
            },
            std::cmp::Ordering::Greater => {other_index += 1},
        }
    }

    base.truncate(base_write_index);
}


#[test]
fn test_union() {
    {
        let mut base = vec![];
        union(&mut base, &vec![]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![0x0];
        union(&mut base, &vec![]);
        assert_eq!(base, vec![0x0]);
    }
    {
        let mut base = vec![];
        union(&mut base, &vec![0x0]);
        assert_eq!(base, vec![0x0]);
    }
    {
        let mut base = vec![0x0, 0x1];
        union(&mut base, &vec![]);
        assert_eq!(base, vec![0x0, 0x1]);
    }
    {
        let mut base = vec![];
        union(&mut base, &vec![0x0, 0x1]);
        assert_eq!(base, vec![0x0, 0x1]);
    }
    {
        let mut base = vec![0xff];
        union(&mut base, &vec![0x0, 0xff]);
        assert_eq!(base, vec![0x0, 0xff]);
    }
    {
        let mut base = vec![0xff];
        union(&mut base, &vec![0xff, 0x0]);
        assert_eq!(base, vec![0x0, 0xff]);
    }
    {
        let mut base = vec![0x0, 0x1];
        union(&mut base, &vec![0x0, 0x1, 0xff]);
        assert_eq!(base, vec![0x0, 0x1, 0xff]);
    }
    {
        let mut base = vec![0xff, 0x0, 0xff];
        union(&mut base, &vec![0x1, 0x0]);
        assert_eq!(base, vec![0x0, 0x1, 0xff]);
    }
}

#[test]
fn test_intersection() {
    {
        let mut base = vec![];
        intersection(&mut base, &[]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![0x0];
        intersection(&mut base, &[]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![];
        intersection(&mut base, &[0x0]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![0x0, 0x1];
        intersection(&mut base, &[]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![];
        intersection(&mut base, &[0x0, 0x1]);
        assert!(base.is_empty());
    }
    {
        let mut base = vec![0x0];
        intersection(&mut base, &[0x0]);
        assert_eq!(base, vec![0x0]);
    }
    {
        let mut base = vec![0xff];
        intersection(&mut base, &[0x0, 0xff]);
        assert_eq!(base, vec![0xff]);
    }
    {
        let mut base = vec![0xff];
        intersection(&mut base, &[0xff, 0x0]);
        assert_eq!(base, vec![0xff]);
    }
    {
        let mut base = vec![0x0, 0x1];
        intersection(&mut base, &[0x0, 0x1, 0xff]);
        assert_eq!(base, vec![0x0, 0x1]);
    }
    {
        let mut base = vec![0x1, 0xff];
        intersection(&mut base, &[0x0, 0x1]);
        assert_eq!(base, vec![0x1]);
    }
}

#[test]
fn test_into_trigrams() {
    assert_eq!(into_trigrams(&[]), Vec::<u32>::new());
    assert_eq!(into_trigrams(&[0x10, 0xff]), Vec::<u32>::new());
    assert_eq!(into_trigrams(&[0x10, 0xff, 0x44]), vec![0x10ff44]);
    assert_eq!(into_trigrams(&[0x10, 0xff, 0x44, 0x22]), vec![0x10ff44, 0xff4422]);
}

