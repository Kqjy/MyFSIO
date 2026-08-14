pub mod eval;
pub mod input;
pub mod plan;
pub mod value;

use eval::{eval, truthiness, AggAccumulator, Record};
use input::RecordSource;
use plan::{ProjItem, SelectPlan};
use value::Value;

pub use plan::plan_query;

const CHUNK_SIZE: usize = 65_536;

#[derive(Clone)]
pub enum OutputFormatCfg {
    Csv {
        field_delimiter: String,
        record_delimiter: String,
        quote: String,
        quote_always: bool,
    },
    Json {
        record_delimiter: String,
    },
}

pub fn run_select(
    source: &mut dyn RecordSource,
    plan: &SelectPlan,
    output: &OutputFormatCfg,
    emit: &mut dyn FnMut(Vec<u8>) -> Result<(), String>,
    cancelled: &dyn Fn() -> bool,
) -> Result<u64, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(CHUNK_SIZE);
    let mut returned: u64 = 0;
    let limit = plan.limit.unwrap_or(u64::MAX);

    if plan.aggregates.is_empty() {
        let mut emitted: u64 = 0;
        if limit > 0 {
            while let Some(record) = source.next_record()? {
                if cancelled() {
                    return Err("client disconnected".to_string());
                }
                if !passes_where(plan, &record)? {
                    continue;
                }
                let fields = project_record(plan, &record, &[])?;
                serialize_row(output, &fields, &mut buffer)?;
                flush_full_chunks(&mut buffer, &mut returned, emit)?;
                emitted += 1;
                if emitted >= limit {
                    break;
                }
            }
        }
    } else {
        let mut acc = AggAccumulator::new(&plan.aggregates);
        while let Some(record) = source.next_record()? {
            if cancelled() {
                return Err("client disconnected".to_string());
            }
            if !passes_where(plan, &record)? {
                continue;
            }
            acc.accumulate(&record)?;
        }
        if limit > 0 {
            let agg_results = acc.finish();
            let empty = Record::Tabular {
                columns: std::sync::Arc::new(Vec::new()),
                values: Vec::new(),
            };
            let fields = project_record(plan, &empty, &agg_results)?;
            serialize_row(output, &fields, &mut buffer)?;
        }
    }

    if !buffer.is_empty() {
        returned += buffer.len() as u64;
        emit(std::mem::take(&mut buffer))?;
    }
    Ok(returned)
}

fn passes_where(plan: &SelectPlan, record: &Record) -> Result<bool, String> {
    match &plan.where_clause {
        None => Ok(true),
        Some(cond) => {
            let v = eval(cond, record, &[])?;
            Ok(truthiness(&v) == Some(true))
        }
    }
}

fn project_record(
    plan: &SelectPlan,
    record: &Record,
    agg_results: &[Value],
) -> Result<Vec<(String, Value)>, String> {
    let mut fields = Vec::with_capacity(plan.projection.len());
    for item in &plan.projection {
        match item {
            ProjItem::Wildcard => fields.extend(record.fields()),
            ProjItem::Expr { expr, name } => {
                fields.push((name.clone(), eval(expr, record, agg_results)?));
            }
        }
    }
    Ok(fields)
}

fn flush_full_chunks(
    buffer: &mut Vec<u8>,
    returned: &mut u64,
    emit: &mut dyn FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    while buffer.len() >= CHUNK_SIZE {
        let rest = buffer.split_off(CHUNK_SIZE);
        let chunk = std::mem::replace(buffer, rest);
        *returned += chunk.len() as u64;
        emit(chunk)?;
    }
    Ok(())
}

fn serialize_row(
    output: &OutputFormatCfg,
    fields: &[(String, Value)],
    buffer: &mut Vec<u8>,
) -> Result<(), String> {
    match output {
        OutputFormatCfg::Csv {
            field_delimiter,
            record_delimiter,
            quote,
            quote_always,
        } => {
            for (i, (_, value)) in fields.iter().enumerate() {
                if i > 0 {
                    buffer.extend_from_slice(field_delimiter.as_bytes());
                }
                let text = if value.is_absent() {
                    String::new()
                } else {
                    value.to_text()
                };
                if *quote_always
                    || (!text.is_empty()
                        && (text.contains(field_delimiter.as_str())
                            || text.contains(quote.as_str())
                            || text.contains(record_delimiter.as_str())))
                {
                    let doubled = text.replace(quote.as_str(), &format!("{}{}", quote, quote));
                    buffer.extend_from_slice(quote.as_bytes());
                    buffer.extend_from_slice(doubled.as_bytes());
                    buffer.extend_from_slice(quote.as_bytes());
                } else {
                    buffer.extend_from_slice(text.as_bytes());
                }
            }
            buffer.extend_from_slice(record_delimiter.as_bytes());
        }
        OutputFormatCfg::Json { record_delimiter } => {
            buffer.push(b'{');
            let mut first = true;
            for (name, value) in fields {
                if matches!(value, Value::Missing) {
                    continue;
                }
                if !first {
                    buffer.push(b',');
                }
                first = false;
                let key = serde_json::to_string(name)
                    .map_err(|e| format!("JSON output encoding failed: {}", e))?;
                buffer.extend_from_slice(key.as_bytes());
                buffer.push(b':');
                let encoded = serde_json::to_string(&value.to_json())
                    .map_err(|e| format!("JSON output encoding failed: {}", e))?;
                buffer.extend_from_slice(encoded.as_bytes());
            }
            buffer.push(b'}');
            buffer.extend_from_slice(record_delimiter.as_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;

    use super::input::{CsvHeaderMode, CsvSource, JsonSource, ParquetSource};
    use super::{plan_query, run_select, OutputFormatCfg};

    fn json_output() -> OutputFormatCfg {
        OutputFormatCfg::Json {
            record_delimiter: "\n".to_string(),
        }
    }

    fn csv_output() -> OutputFormatCfg {
        OutputFormatCfg::Csv {
            field_delimiter: ",".to_string(),
            record_delimiter: "\n".to_string(),
            quote: "\"".to_string(),
            quote_always: false,
        }
    }

    fn run_csv(
        sql: &str,
        data: &str,
        header: &str,
        output: OutputFormatCfg,
    ) -> Result<String, String> {
        let plan = plan_query(sql)?;
        let mut source = CsvSource::new(
            Box::new(std::io::Cursor::new(data.as_bytes().to_vec())),
            b',',
            b'"',
            None,
            CsvHeaderMode::from_file_header_info(header),
        )?;
        let mut out = Vec::new();
        let mut emit = |chunk: Vec<u8>| {
            out.extend_from_slice(&chunk);
            Ok(())
        };
        run_select(&mut source, &plan, &output, &mut emit, &|| false)?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn run_json(sql: &str, data: &str, document_mode: bool) -> Result<String, String> {
        let plan = plan_query(sql)?;
        let mut source = JsonSource::new(
            Box::new(std::io::Cursor::new(data.as_bytes().to_vec())),
            document_mode,
        );
        let mut out = Vec::new();
        let mut emit = |chunk: Vec<u8>| {
            out.extend_from_slice(&chunk);
            Ok(())
        };
        run_select(&mut source, &plan, &json_output(), &mut emit, &|| false)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn parser_rejects_non_select_statements() {
        for sql in [
            "DROP TABLE s3object",
            "INSERT INTO s3object VALUES (1)",
            "UPDATE s3object SET a = 1",
            "DELETE FROM s3object",
            "CREATE TABLE t (a INT)",
            "ATTACH 'x.db'",
            "SELECT 1; SELECT 2",
        ] {
            assert!(plan_query(sql).is_err(), "should reject: {}", sql);
        }
    }

    #[test]
    fn parser_rejects_unsupported_clauses() {
        for sql in [
            "SELECT a FROM s3object GROUP BY a",
            "SELECT a FROM s3object ORDER BY a",
            "SELECT DISTINCT a FROM s3object",
            "SELECT a FROM s3object LIMIT 5 OFFSET 2",
            "SELECT a FROM s3object t1 JOIN other t2 ON t1.a = t2.a",
            "SELECT (SELECT 1) FROM s3object",
            "SELECT a FROM s3object WHERE b IN (SELECT c FROM s3object)",
            "SELECT read_csv('/etc/passwd') FROM s3object",
            "SELECT * FROM read_parquet('x')",
            "WITH t AS (SELECT 1) SELECT * FROM t",
            "SELECT COUNT(*) FROM s3object HAVING COUNT(*) > 1",
            "SELECT a, COUNT(*) FROM s3object",
        ] {
            assert!(plan_query(sql).is_err(), "should reject: {}", sql);
        }
    }

    #[test]
    fn parser_accepts_select_subset() {
        for sql in [
            "SELECT * FROM s3object",
            "SELECT s.* FROM s3object s",
            "SELECT name, age FROM S3Object WHERE CAST(age AS INTEGER) >= 35",
            "SELECT COUNT(*), SUM(a), MIN(a), MAX(a), AVG(a) FROM s3object",
            "SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END FROM s3object",
            "SELECT a FROM s3object WHERE b LIKE 'x%' ESCAPE '!'",
            "SELECT a FROM s3object WHERE b BETWEEN 1 AND 5 AND c IN (1, 2)",
            "SELECT COALESCE(a, b), NULLIF(a, b), TRIM(c) FROM s3object",
            "SELECT SUBSTRING(a, 2, 3), UPPER(b), LOWER(c) FROM s3object LIMIT 10",
            "SELECT s.a, s.b.c FROM s3object AS s WHERE s.a IS NOT NULL",
        ] {
            assert!(
                plan_query(sql).is_ok(),
                "should accept: {}: {:?}",
                sql,
                plan_query(sql).err()
            );
        }
    }

    #[test]
    fn csv_header_modes_name_columns() {
        let data = "name,age\nalice,30\nbob,40\n";
        let with_names = run_csv("SELECT name FROM s3object", data, "USE", json_output()).unwrap();
        assert_eq!(with_names, "{\"name\":\"alice\"}\n{\"name\":\"bob\"}\n");

        let ignored = run_csv("SELECT _1 FROM s3object", data, "IGNORE", json_output()).unwrap();
        assert_eq!(ignored, "{\"_1\":\"alice\"}\n{\"_1\":\"bob\"}\n");

        let none = run_csv("SELECT _2 FROM s3object", data, "NONE", json_output()).unwrap();
        assert_eq!(none, "{\"_2\":\"age\"}\n{\"_2\":30}\n{\"_2\":40}\n");
    }

    #[test]
    fn csv_output_quotes_only_when_needed() {
        let data = "a,b\n\"x,y\",plain\n\"say \"\"hi\"\"\",2\n";
        let out = run_csv("SELECT a, b FROM s3object", data, "USE", csv_output()).unwrap();
        assert_eq!(out, "\"x,y\",plain\n\"say \"\"hi\"\"\",2\n");
    }

    #[test]
    fn like_patterns_and_escape() {
        let data = "v\nfoo\nf_o\nbar\nfo\n";
        let out = run_csv(
            "SELECT v FROM s3object WHERE v LIKE 'f_o'",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(out, "foo\nf_o\n");

        let escaped = run_csv(
            "SELECT v FROM s3object WHERE v LIKE 'f!_o' ESCAPE '!'",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(escaped, "f_o\n");

        let pct = run_csv(
            "SELECT v FROM s3object WHERE v LIKE 'f%'",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(pct, "foo\nf_o\nfo\n");
    }

    #[test]
    fn null_semantics() {
        let data = "a,b\n1,\n,2\n3,4\n";
        let out = run_csv(
            "SELECT a FROM s3object WHERE b IS NULL",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(out, "1\n");

        let not_null = run_csv(
            "SELECT a FROM s3object WHERE b IS NOT NULL AND a IS NOT NULL",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(not_null, "3\n");

        let coalesced = run_csv(
            "SELECT COALESCE(a, b, 99) FROM s3object",
            data,
            "USE",
            csv_output(),
        )
        .unwrap();
        assert_eq!(coalesced, "1\n2\n3\n");
    }

    #[test]
    fn aggregates_over_empty_set() {
        let data = "a\n1\n2\n";
        let out = run_csv(
            "SELECT COUNT(*) AS c, SUM(a) AS s, AVG(a) AS m, MIN(a) AS lo FROM s3object WHERE a > 100",
            data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(out, "{\"c\":0,\"s\":null,\"m\":null,\"lo\":null}\n");
    }

    #[test]
    fn count_expr_skips_nulls() {
        let data = "a,b\n1,x\n,y\n3,z\n";
        let out = run_csv(
            "SELECT COUNT(a) AS c, COUNT(*) AS all_rows FROM s3object",
            data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(out, "{\"c\":2,\"all_rows\":3}\n");
    }

    #[test]
    fn limit_zero_and_limit_stops_early() {
        let data = "a\n1\n2\n3\n";
        let none = run_csv("SELECT a FROM s3object LIMIT 0", data, "USE", csv_output()).unwrap();
        assert_eq!(none, "");
        let two = run_csv("SELECT a FROM s3object LIMIT 2", data, "USE", csv_output()).unwrap();
        assert_eq!(two, "1\n2\n");
    }

    #[test]
    fn json_lines_and_nested_paths() {
        let data = "{\"user\":{\"name\":\"amy\",\"meta\":{\"age\":31}},\"ok\":true}\n{\"user\":{\"name\":\"joe\",\"meta\":{\"age\":22}},\"ok\":false}\n";
        let out = run_json(
            "SELECT s.user.name AS n, s.user.meta.age AS a FROM s3object s WHERE s.ok = true",
            data,
            false,
        )
        .unwrap();
        assert_eq!(out, "{\"n\":\"amy\",\"a\":31}\n");
    }

    #[test]
    fn json_document_array_flattens() {
        let data = "[{\"id\":1},{\"id\":2},{\"id\":3}]";
        let out = run_json("SELECT id FROM s3object WHERE id > 1", data, true).unwrap();
        assert_eq!(out, "{\"id\":2}\n{\"id\":3}\n");
    }

    #[test]
    fn json_missing_fields_are_omitted() {
        let data = "{\"a\":1,\"b\":2}\n{\"a\":3}\n";
        let out = run_json("SELECT a, b FROM s3object", data, false).unwrap();
        assert_eq!(out, "{\"a\":1,\"b\":2}\n{\"a\":3}\n");

        let star = run_json("SELECT * FROM s3object", data, false).unwrap();
        assert_eq!(star, "{\"a\":1,\"b\":2}\n{\"a\":3}\n");
    }

    #[test]
    fn case_cast_and_arithmetic() {
        let data = "a\n1\n2\n3\n";
        let out = run_csv(
            "SELECT a, a * 10 AS big, CASE a WHEN 1 THEN 'one' WHEN 2 THEN 'two' ELSE 'many' END AS w, CAST(a AS VARCHAR) AS s FROM s3object",
            data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(
            out,
            "{\"a\":1,\"big\":10,\"w\":\"one\",\"s\":\"1\"}\n{\"a\":2,\"big\":20,\"w\":\"two\",\"s\":\"2\"}\n{\"a\":3,\"big\":30,\"w\":\"many\",\"s\":\"3\"}\n"
        );
    }

    #[test]
    fn division_yields_float_and_null_on_zero() {
        let data = "a,b\n10,4\n10,0\n";
        let out = run_csv(
            "SELECT a / b AS q FROM s3object",
            data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(out, "{\"q\":2.5}\n{\"q\":null}\n");
    }

    #[test]
    fn string_functions() {
        let data = "v\n  pad  \n";
        let out = run_csv(
            "SELECT TRIM(v) AS t, UPPER(TRIM(v)) AS u, CHAR_LENGTH(TRIM(v)) AS l, SUBSTRING(TRIM(v), 2, 2) AS sub FROM s3object",
            data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(
            out,
            "{\"t\":\"pad\",\"u\":\"PAD\",\"l\":3,\"sub\":\"ad\"}\n"
        );
    }

    #[test]
    fn from_clause_is_restricted_to_s3object() {
        for sql in [
            "SELECT a FROM data",
            "SELECT a FROM other_table",
            "SELECT a FROM db.s3object",
            "SELECT x.* FROM s3object s",
        ] {
            assert!(plan_query(sql).is_err(), "should reject: {}", sql);
        }
        for sql in [
            "SELECT a FROM s3object",
            "SELECT a FROM S3OBJECT",
            "SELECT s.* FROM s3object s",
            "SELECT s3object.a FROM s3object",
        ] {
            assert!(
                plan_query(sql).is_ok(),
                "should accept: {}: {:?}",
                sql,
                plan_query(sql).err()
            );
        }
    }

    #[test]
    fn cancellation_stops_aggregate_scan_early() {
        struct EndlessSource {
            served: usize,
        }
        impl super::input::RecordSource for EndlessSource {
            fn next_record(&mut self) -> Result<Option<super::eval::Record>, String> {
                self.served += 1;
                Ok(Some(super::eval::Record::Tabular {
                    columns: Arc::new(vec!["a".to_string()]),
                    values: vec![super::value::Value::Int(1)],
                }))
            }
        }

        let plan = plan_query("SELECT COUNT(*) FROM s3object").unwrap();
        let mut source = EndlessSource { served: 0 };
        let mut emit = |_chunk: Vec<u8>| Ok(());
        let calls = std::cell::Cell::new(0usize);
        let cancelled = || {
            calls.set(calls.get() + 1);
            calls.get() > 5
        };
        let err =
            run_select(&mut source, &plan, &json_output(), &mut emit, &cancelled).unwrap_err();
        assert!(err.contains("disconnected"), "got: {}", err);
        assert!(
            source.served <= 7,
            "scan should stop promptly, served {}",
            source.served
        );
    }

    #[test]
    fn quote_fields_always_quotes_everything() {
        let output = OutputFormatCfg::Csv {
            field_delimiter: ",".to_string(),
            record_delimiter: "\n".to_string(),
            quote: "\"".to_string(),
            quote_always: true,
        };
        let out = run_csv("SELECT a, b FROM s3object", "a,b\nx,1\n", "USE", output).unwrap();
        assert_eq!(out, "\"x\",\"1\"\n");
    }

    #[test]
    fn csv_comment_lines_are_skipped() {
        let data = "a,b\n#note,skipped\n1,2\n";
        let plan = plan_query("SELECT a FROM s3object").unwrap();
        let mut source = CsvSource::new(
            Box::new(std::io::Cursor::new(data.as_bytes().to_vec())),
            b',',
            b'"',
            Some(b'#'),
            CsvHeaderMode::from_file_header_info("USE"),
        )
        .unwrap();
        let mut out = Vec::new();
        let mut emit = |chunk: Vec<u8>| {
            out.extend_from_slice(&chunk);
            Ok(())
        };
        run_select(&mut source, &plan, &csv_output(), &mut emit, &|| false).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "1\n");
    }

    #[test]
    fn oversized_csv_record_is_rejected_without_buffering_it() {
        let mut data = String::from("a,b\n1,");
        data.push_str(&"x".repeat(5 * 1024 * 1024));
        data.push('\n');
        let err = run_csv("SELECT a FROM s3object", &data, "USE", csv_output()).unwrap_err();
        assert!(
            err.contains("exceeds the maximum supported size"),
            "got: {}",
            err
        );
    }

    #[test]
    fn oversized_json_record_is_rejected() {
        let mut data = String::from("{\"a\":\"");
        data.push_str(&"y".repeat(17 * 1024 * 1024));
        data.push_str("\"}\n");
        let err = run_json("SELECT a FROM s3object", &data, false).unwrap_err();
        assert!(
            err.contains("exceeds the maximum supported size"),
            "got: {}",
            err
        );
    }

    #[test]
    fn large_input_of_small_records_still_streams() {
        let mut data = String::from("a,b\n");
        for i in 0..50_000 {
            data.push_str(&format!("{},{}\n", i, "v".repeat(64)));
        }
        let out = run_csv(
            "SELECT COUNT(*) AS c FROM s3object",
            &data,
            "USE",
            json_output(),
        )
        .unwrap();
        assert_eq!(out, "{\"c\":50000}\n");
    }

    #[test]
    fn malformed_json_reports_error() {
        let err = run_json("SELECT * FROM s3object", "{\"a\": 1}\n{oops}", false).unwrap_err();
        assert!(err.contains("Malformed JSON input"), "got: {}", err);
    }

    #[test]
    fn parquet_round_trip() {
        use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int64Type};
        use parquet::file::properties::WriterProperties;
        use parquet::file::writer::SerializedFileWriter;
        use parquet::schema::parser::parse_message_type;

        let schema = Arc::new(
            parse_message_type(
                "message rows { required int64 id; required binary name (UTF8); optional double score; }",
            )
            .unwrap(),
        );
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let file = tmp.as_file_mut().try_clone().unwrap();
            let mut writer = SerializedFileWriter::new(
                file,
                schema,
                Arc::new(WriterProperties::builder().build()),
            )
            .unwrap();
            let mut rg = writer.next_row_group().unwrap();
            let mut ids = rg.next_column().unwrap().unwrap();
            ids.typed::<Int64Type>()
                .write_batch(&[1, 2, 3], None, None)
                .unwrap();
            ids.close().unwrap();
            let mut names = rg.next_column().unwrap().unwrap();
            names
                .typed::<ByteArrayType>()
                .write_batch(
                    &[
                        ByteArray::from("alice"),
                        ByteArray::from("bob"),
                        ByteArray::from("carol"),
                    ],
                    None,
                    None,
                )
                .unwrap();
            names.close().unwrap();
            let mut scores = rg.next_column().unwrap().unwrap();
            scores
                .typed::<DoubleType>()
                .write_batch(&[9.5, 7.25], Some(&[1, 0, 1]), None)
                .unwrap();
            scores.close().unwrap();
            rg.close().unwrap();
            writer.close().unwrap();
        }
        tmp.flush().unwrap();

        let plan = plan_query("SELECT name, score FROM s3object WHERE id >= 2").unwrap();
        let file = std::fs::File::open(tmp.path()).unwrap();
        let mut source = ParquetSource::new(file).unwrap();
        let mut out = Vec::new();
        let mut emit = |chunk: Vec<u8>| {
            out.extend_from_slice(&chunk);
            Ok(())
        };
        run_select(&mut source, &plan, &json_output(), &mut emit, &|| false).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"name\":\"bob\",\"score\":null}\n{\"name\":\"carol\",\"score\":7.25}\n"
        );
    }
}
