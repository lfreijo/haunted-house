//! Prometheus metrics for the haunted-house worker.

use lazy_static::lazy_static;
use prometheus::{
    self, Counter, Gauge, GaugeVec, Histogram, HistogramOpts, IntGauge, Opts, Registry,
    TextEncoder, Encoder,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // ========================================================================
    // Worker: ingestion metrics (fetcher subsystem)
    // ========================================================================

    /// Total number of files ingested (written to journal).
    pub static ref FETCHER_FILES_INGESTED: Counter = Counter::with_opts(
        Opts::new("haunted_house_fetcher_files_ingested_total", "Total number of files written to journal filters.")
    ).unwrap();

    /// Total trigram load/download errors during ingestion.
    pub static ref FETCHER_ERRORS: Counter = Counter::with_opts(
        Opts::new("haunted_house_fetcher_errors_total", "Total number of trigram fetch/download errors.")
    ).unwrap();

    /// Total files rejected during ingestion (e.g. blob not found after retries).
    pub static ref FETCHER_REJECTED: Counter = Counter::with_opts(
        Opts::new("haunted_house_fetcher_rejected_total", "Total files rejected during ingestion.")
    ).unwrap();

    /// Number of S3 downloads currently in flight.
    pub static ref FETCHER_ACTIVE_DOWNLOADS: IntGauge = IntGauge::new(
        "haunted_house_fetcher_active_downloads", "Number of S3 trigram downloads currently in flight."
    ).unwrap();

    /// Duration of individual S3 trigram file downloads.
    pub static ref FETCHER_DOWNLOAD_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_fetcher_download_duration_seconds", "Duration of individual S3 trigram file downloads.")
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0])
    ).unwrap();

    /// Number of files per ingest batch.
    pub static ref FETCHER_BATCH_SIZE: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_fetcher_batch_size", "Number of files per ingest batch.")
            .buckets(vec![0.0, 10.0, 25.0, 50.0, 75.0, 100.0, 200.0, 500.0])
    ).unwrap();

    /// Total batches written to journal.
    pub static ref FETCHER_BATCHES_WRITTEN: Counter = Counter::with_opts(
        Opts::new("haunted_house_fetcher_batches_written_total", "Total number of batches written to journal.")
    ).unwrap();

    // ========================================================================
    // Worker: ingest pipeline phase timing (histograms)
    // ========================================================================

    /// Time to fetch batch metadata from SQLite.
    pub static ref INGEST_GET_BATCH_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_ingest_get_batch_duration_seconds", "Time to fetch ingest batch from SQLite.")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
    ).unwrap();

    /// Time to load trigram data for a batch.
    pub static ref INGEST_TRIGRAM_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_ingest_trigram_duration_seconds", "Time to load trigram data for a batch.")
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0])
    ).unwrap();

    /// Time to write batch to journal (write_batch).
    pub static ref INGEST_WRITE_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_ingest_write_duration_seconds", "Time to write batch to journal.")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0])
    ).unwrap();

    /// Time for finished_ingest DB update.
    pub static ref INGEST_FINISH_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_ingest_finish_duration_seconds", "Time for finished_ingest DB update.")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
    ).unwrap();

    // ========================================================================
    // Worker: scanning metrics (YARA)
    // ========================================================================

    /// Total number of YARA scan jobs started.
    pub static ref SCANNER_SCANS_STARTED: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_scans_started_total", "Total number of YARA scan jobs started.")
    ).unwrap();

    /// Total number of YARA scan jobs completed successfully.
    pub static ref SCANNER_SCANS_COMPLETED: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_scans_completed_total", "Total number of YARA scan jobs completed successfully.")
    ).unwrap();

    /// Total number of YARA scan jobs that ended in error.
    pub static ref SCANNER_SCANS_ERRORED: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_scans_errored_total", "Total number of YARA scan jobs that ended in error.")
    ).unwrap();

    /// Wall-clock duration of YARA scan jobs.
    pub static ref SCANNER_SCAN_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_scanner_scan_duration_seconds", "Wall-clock duration of YARA scan jobs.")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0])
    ).unwrap();

    /// Total number of files scanned by YARA across all jobs.
    pub static ref SCANNER_FILES_SCANNED: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_files_scanned_total", "Total number of files scanned by YARA across all jobs.")
    ).unwrap();

    /// Total files skipped during scans (file not available).
    pub static ref SCANNER_FILES_SKIPPED: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_files_skipped_total", "Total files skipped during scans (file not available).")
    ).unwrap();

    /// Total number of YARA rule matches found across all jobs.
    pub static ref SCANNER_HITS: Counter = Counter::with_opts(
        Opts::new("haunted_house_scanner_hits_total", "Total number of YARA rule matches found across all jobs.")
    ).unwrap();

    /// Number of currently running YARA scan jobs.
    pub static ref SCANNER_ACTIVE_SCANS: IntGauge = IntGauge::new(
        "haunted_house_scanner_active_scans", "Number of currently running YARA scan jobs."
    ).unwrap();

    // ========================================================================
    // Worker: storage metrics
    // ========================================================================

    /// Free disk space in bytes on the data volume.
    pub static ref STORAGE_DISK_FREE_BYTES: Gauge = Gauge::new(
        "haunted_house_storage_disk_free_bytes", "Free disk space in bytes on the data volume."
    ).unwrap();

    /// Total disk space in bytes on the data volume.
    pub static ref STORAGE_DISK_TOTAL_BYTES: Gauge = Gauge::new(
        "haunted_house_storage_disk_total_bytes", "Total disk space in bytes on the data volume."
    ).unwrap();

    /// Percentage of disk space used (0-100).
    pub static ref STORAGE_DISK_USED_PERCENT: Gauge = Gauge::new(
        "haunted_house_storage_disk_used_percent", "Percentage of disk space used (0-100)."
    ).unwrap();

    /// Total number of active filters.
    pub static ref STORAGE_FILTERS_TOTAL: IntGauge = IntGauge::new(
        "haunted_house_storage_filters_total", "Total number of active filters."
    ).unwrap();

    /// Total size of filter data in bytes (used storage on data volume).
    pub static ref STORAGE_BYTES_TOTAL: Gauge = Gauge::new(
        "haunted_house_storage_bytes_total", "Total size of filter data in bytes."
    ).unwrap();

    /// Whether the worker is under storage pressure (1 = true, 0 = false).
    pub static ref STORAGE_PRESSURE: IntGauge = IntGauge::new(
        "haunted_house_storage_pressure", "Whether the worker is under storage pressure (1=yes, 0=no)."
    ).unwrap();

    // ========================================================================
    // Worker: GC metrics
    // ========================================================================

    /// Total number of filters evicted due to disk pressure.
    pub static ref GC_FILTERS_EVICTED: Counter = Counter::with_opts(
        Opts::new("haunted_house_gc_filters_evicted_total", "Total number of filters evicted due to disk pressure.")
    ).unwrap();

    /// Total number of expired filters deleted.
    pub static ref GC_FILTERS_EXPIRED: Counter = Counter::with_opts(
        Opts::new("haunted_house_gc_filters_expired_total", "Total number of expired filters deleted.")
    ).unwrap();

    /// Duration of GC eviction/expiry runs.
    pub static ref GC_RUN_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_gc_run_duration_seconds", "Duration of GC eviction/expiry runs.")
            .buckets(vec![0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0])
    ).unwrap();

    // ========================================================================
    // Broker: fetcher metrics
    // ========================================================================

    /// Seconds between checkpoint timestamp and now (ingestion lag).
    pub static ref BROKER_CHECKPOINT_LAG: Gauge = Gauge::new(
        "haunted_house_broker_checkpoint_lag_seconds", "Seconds between checkpoint timestamp and now (ingestion lag)."
    ).unwrap();

    /// Seconds between read cursor and now (how far behind ES polling is).
    pub static ref BROKER_READ_CURSOR_LAG: Gauge = Gauge::new(
        "haunted_house_broker_read_cursor_lag_seconds", "Seconds between read cursor and now."
    ).unwrap();

    /// Files pending ingestion (not yet assigned to workers).
    pub static ref BROKER_PENDING_FILES: Gauge = Gauge::new(
        "haunted_house_broker_pending_files", "Files pending ingestion (not yet assigned to workers)."
    ).unwrap();

    /// Files currently in flight (being ingested).
    pub static ref BROKER_INFLIGHT: Gauge = Gauge::new(
        "haunted_house_broker_inflight", "Files currently in flight in the fetcher."
    ).unwrap();

    /// ES queries per minute by the file fetcher.
    pub static ref BROKER_FETCHER_SEARCHES_PER_MIN: Gauge = Gauge::new(
        "haunted_house_broker_fetcher_searches_per_minute", "ES queries per minute by the file fetcher."
    ).unwrap();

    /// Files processed per minute by the file fetcher.
    pub static ref BROKER_FETCHER_THROUGHPUT_PER_MIN: Gauge = Gauge::new(
        "haunted_house_broker_fetcher_throughput_per_minute", "Files processed per minute by the file fetcher."
    ).unwrap();

    /// Retry attempts per minute in the file fetcher.
    pub static ref BROKER_FETCHER_RETRIES_PER_MIN: Gauge = Gauge::new(
        "haunted_house_broker_fetcher_retries_per_minute", "Retry attempts per minute in the file fetcher."
    ).unwrap();

    /// Rows returned by last ES fetch query.
    pub static ref BROKER_LAST_FETCH_ROWS: Gauge = Gauge::new(
        "haunted_house_broker_last_fetch_rows", "Rows returned by the last ES fetch query."
    ).unwrap();

    // ========================================================================
    // Broker: search metrics
    // ========================================================================

    /// Number of currently running searches.
    pub static ref BROKER_ACTIVE_SEARCHES: IntGauge = IntGauge::new(
        "haunted_house_broker_active_searches", "Number of currently running searches."
    ).unwrap();

    /// Total number of searches submitted.
    pub static ref BROKER_SEARCHES_SUBMITTED: Counter = Counter::with_opts(
        Opts::new("haunted_house_broker_searches_submitted_total", "Total number of search requests submitted.")
    ).unwrap();

    /// Total number of searches completed successfully.
    pub static ref BROKER_SEARCHES_COMPLETED: Counter = Counter::with_opts(
        Opts::new("haunted_house_broker_searches_completed_total", "Total number of searches completed successfully.")
    ).unwrap();

    /// Wall-clock duration of searches.
    pub static ref BROKER_SEARCH_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("haunted_house_broker_search_duration_seconds", "End-to-end duration of searches.")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0])
    ).unwrap();

    // ========================================================================
    // Process metrics
    // ========================================================================

    /// Build information (version, role). Always 1.
    pub static ref BUILD_INFO: GaugeVec = GaugeVec::new(
        Opts::new("haunted_house_build_info", "Build information (version, role). Always 1."),
        &["version", "role"]
    ).unwrap();

    /// Seconds since process start.
    pub static ref UPTIME_SECONDS: Gauge = Gauge::new(
        "haunted_house_uptime_seconds", "Seconds since process start."
    ).unwrap();
}

/// Register all metrics with the global registry.
pub fn register_metrics() {
    // Fetcher / ingestion
    REGISTRY.register(Box::new(FETCHER_FILES_INGESTED.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_ERRORS.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_REJECTED.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_ACTIVE_DOWNLOADS.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_DOWNLOAD_DURATION.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_BATCH_SIZE.clone())).unwrap();
    REGISTRY.register(Box::new(FETCHER_BATCHES_WRITTEN.clone())).unwrap();

    // Ingest pipeline timing
    REGISTRY.register(Box::new(INGEST_GET_BATCH_DURATION.clone())).unwrap();
    REGISTRY.register(Box::new(INGEST_TRIGRAM_DURATION.clone())).unwrap();
    REGISTRY.register(Box::new(INGEST_WRITE_DURATION.clone())).unwrap();
    REGISTRY.register(Box::new(INGEST_FINISH_DURATION.clone())).unwrap();

    // Scanner / YARA
    REGISTRY.register(Box::new(SCANNER_SCANS_STARTED.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_SCANS_COMPLETED.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_SCANS_ERRORED.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_SCAN_DURATION.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_FILES_SCANNED.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_FILES_SKIPPED.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_HITS.clone())).unwrap();
    REGISTRY.register(Box::new(SCANNER_ACTIVE_SCANS.clone())).unwrap();

    // Storage
    REGISTRY.register(Box::new(STORAGE_DISK_FREE_BYTES.clone())).unwrap();
    REGISTRY.register(Box::new(STORAGE_DISK_TOTAL_BYTES.clone())).unwrap();
    REGISTRY.register(Box::new(STORAGE_DISK_USED_PERCENT.clone())).unwrap();
    REGISTRY.register(Box::new(STORAGE_FILTERS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(STORAGE_BYTES_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(STORAGE_PRESSURE.clone())).unwrap();

    // GC
    REGISTRY.register(Box::new(GC_FILTERS_EVICTED.clone())).unwrap();
    REGISTRY.register(Box::new(GC_FILTERS_EXPIRED.clone())).unwrap();
    REGISTRY.register(Box::new(GC_RUN_DURATION.clone())).unwrap();

    // Process
    REGISTRY.register(Box::new(BUILD_INFO.clone())).unwrap();
    REGISTRY.register(Box::new(UPTIME_SECONDS.clone())).unwrap();
}

/// Register broker-specific metrics with the global registry.
pub fn register_broker_metrics() {
    REGISTRY.register(Box::new(BROKER_CHECKPOINT_LAG.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_READ_CURSOR_LAG.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_PENDING_FILES.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_INFLIGHT.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_FETCHER_SEARCHES_PER_MIN.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_FETCHER_THROUGHPUT_PER_MIN.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_FETCHER_RETRIES_PER_MIN.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_LAST_FETCH_ROWS.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_ACTIVE_SEARCHES.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_SEARCHES_SUBMITTED.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_SEARCHES_COMPLETED.clone())).unwrap();
    REGISTRY.register(Box::new(BROKER_SEARCH_DURATION.clone())).unwrap();

    // Process (shared)
    REGISTRY.register(Box::new(BUILD_INFO.clone())).unwrap();
    REGISTRY.register(Box::new(UPTIME_SECONDS.clone())).unwrap();
}

/// Render all metrics in Prometheus text exposition format.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
