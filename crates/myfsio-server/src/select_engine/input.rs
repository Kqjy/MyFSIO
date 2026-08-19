use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::eval::Record;
use super::value::Value;

pub trait RecordSource {
    fn next_record(&mut self) -> Result<Option<Record>, String>;
}

const CSV_MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const JSON_MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const JSON_MAX_DOCUMENT_BYTES: u64 = 128 * 1024 * 1024;

struct BudgetReader<R> {
    inner: R,
    used: Arc<AtomicU64>,
    limit: u64,
    label: &'static str,
}

impl<R> BudgetReader<R> {
    fn new(inner: R, limit: u64, label: &'static str) -> (BudgetReader<R>, Arc<AtomicU64>) {
        let used = Arc::new(AtomicU64::new(0));
        (
            BudgetReader {
                inner,
                used: used.clone(),
                limit,
                label,
            },
            used,
        )
    }
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.used.load(Ordering::Relaxed) >= self.limit {
            return Err(std::io::Error::other(format!(
                "A single {} exceeds the maximum supported size of {} bytes",
                self.label, self.limit
            )));
        }
        let n = self.inner.read(buf)?;
        self.used.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

pub struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R) -> (CountingReader<R>, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        (
            CountingReader {
                inner,
                count: count.clone(),
            },
            count,
        )
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

pub struct CsvHeaderMode {
    pub use_names: bool,
    pub skip_first: bool,
}

impl CsvHeaderMode {
    pub fn from_file_header_info(info: &str) -> CsvHeaderMode {
        match info {
            "USE" => CsvHeaderMode {
                use_names: true,
                skip_first: true,
            },
            "IGNORE" => CsvHeaderMode {
                use_names: false,
                skip_first: true,
            },
            _ => CsvHeaderMode {
                use_names: false,
                skip_first: false,
            },
        }
    }
}

pub struct CsvSource {
    reader: csv::Reader<Box<dyn Read + Send>>,
    columns: Arc<Vec<String>>,
    record: csv::StringRecord,
    budget: Arc<AtomicU64>,
}

impl CsvSource {
    pub fn new(
        input: Box<dyn Read + Send>,
        delimiter: u8,
        quote: u8,
        comment: Option<u8>,
        header: CsvHeaderMode,
    ) -> Result<CsvSource, String> {
        let (bounded, budget) = BudgetReader::new(input, CSV_MAX_RECORD_BYTES, "CSV record");
        let bounded: Box<dyn Read + Send> = Box::new(bounded);
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .quote(quote)
            .comment(comment)
            .has_headers(header.skip_first)
            .flexible(true)
            .from_reader(bounded);
        let columns = if header.use_names {
            let headers = reader
                .headers()
                .map_err(|e| format!("Failed reading CSV header: {}", e))?;
            headers.iter().map(|h| h.to_string()).collect()
        } else {
            Vec::new()
        };
        budget.store(0, Ordering::Relaxed);
        Ok(CsvSource {
            reader,
            columns: Arc::new(columns),
            record: csv::StringRecord::new(),
            budget,
        })
    }

    fn ensure_columns(&mut self, width: usize) {
        if self.columns.len() < width {
            let mut names = (*self.columns).clone();
            for i in names.len()..width {
                names.push(format!("_{}", i + 1));
            }
            self.columns = Arc::new(names);
        }
    }
}

impl RecordSource for CsvSource {
    fn next_record(&mut self) -> Result<Option<Record>, String> {
        let more = self
            .reader
            .read_record(&mut self.record)
            .map_err(|e| format!("Malformed CSV input: {}", e))?;
        self.budget.store(0, Ordering::Relaxed);
        if !more {
            return Ok(None);
        }
        self.ensure_columns(self.record.len());
        let values: Vec<Value> = self.record.iter().map(Value::infer_from_text).collect();
        Ok(Some(Record::Tabular {
            columns: self.columns.clone(),
            values,
        }))
    }
}

pub struct JsonSource {
    iter: serde_json::StreamDeserializer<
        'static,
        serde_json::de::IoRead<Box<dyn Read + Send>>,
        serde_json::Value,
    >,
    pending: std::collections::VecDeque<serde_json::Value>,
    flatten_arrays: bool,
    budget: Arc<AtomicU64>,
}

impl JsonSource {
    pub fn new(input: Box<dyn Read + Send>, document_mode: bool) -> JsonSource {
        let (limit, label) = if document_mode {
            (JSON_MAX_DOCUMENT_BYTES, "JSON document")
        } else {
            (JSON_MAX_RECORD_BYTES, "JSON record")
        };
        let (bounded, budget) = BudgetReader::new(input, limit, label);
        let bounded: Box<dyn Read + Send> = Box::new(bounded);
        JsonSource {
            iter: serde_json::Deserializer::from_reader(bounded).into_iter(),
            pending: std::collections::VecDeque::new(),
            flatten_arrays: document_mode,
            budget,
        }
    }

    fn to_record(value: serde_json::Value) -> Record {
        match Value::from_json(value) {
            obj @ Value::Object(_) => Record::Document(obj),
            other => Record::Document(Value::Object(vec![("_1".to_string(), other)])),
        }
    }
}

impl RecordSource for JsonSource {
    fn next_record(&mut self) -> Result<Option<Record>, String> {
        loop {
            if let Some(value) = self.pending.pop_front() {
                return Ok(Some(Self::to_record(value)));
            }
            let next = self.iter.next();
            self.budget.store(0, Ordering::Relaxed);
            match next {
                None => return Ok(None),
                Some(Err(e)) => return Err(format!("Malformed JSON input: {}", e)),
                Some(Ok(serde_json::Value::Array(items))) if self.flatten_arrays => {
                    self.pending.extend(items);
                }
                Some(Ok(value)) => return Ok(Some(Self::to_record(value))),
            }
        }
    }
}

pub struct ParquetSource {
    iter: parquet::record::reader::RowIter<'static>,
}

impl ParquetSource {
    pub fn new(file: std::fs::File) -> Result<ParquetSource, String> {
        use parquet::file::reader::SerializedFileReader;
        let reader = SerializedFileReader::new(file)
            .map_err(|e| format!("Failed reading Parquet file: {}", e))?;
        let iter = parquet::record::reader::RowIter::from_file_into(Box::new(reader));
        Ok(ParquetSource { iter })
    }
}

impl RecordSource for ParquetSource {
    fn next_record(&mut self) -> Result<Option<Record>, String> {
        match self.iter.next() {
            None => Ok(None),
            Some(Err(e)) => Err(format!("Failed reading Parquet data: {}", e)),
            Some(Ok(row)) => {
                let json = row.to_json_value();
                Ok(Some(JsonSource::to_record(json)))
            }
        }
    }
}
