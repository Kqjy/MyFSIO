use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];

fn system_time_to_epoch(t: SystemTime) -> f64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn extract_etag_from_meta_bytes(content: &[u8]) -> Option<String> {
    let marker = b"\"__etag__\"";
    let idx = content.windows(marker.len()).position(|w| w == marker)?;
    let after = &content[idx + marker.len()..];
    let start = after.iter().position(|&b| b == b'"')? + 1;
    let rest = &after[start..];
    let end = rest.iter().position(|&b| b == b'"')?;
    std::str::from_utf8(&rest[..end]).ok().map(|s| s.to_owned())
}

fn has_any_file(root: &str) -> bool {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        return false;
    }
    let mut stack = vec![root_path.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry_result in entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_file() {
                return true;
            }
            if ft.is_dir() && !ft.is_symlink() {
                stack.push(entry.path());
            }
        }
    }
    false
}

#[pyfunction]
pub fn write_index_entry(
    py: Python<'_>,
    path: &str,
    entry_name: &str,
    entry_data_json: &str,
) -> PyResult<()> {
    let path_owned = path.to_owned();
    let entry_owned = entry_name.to_owned();
    let data_owned = entry_data_json.to_owned();

    py.detach(move || -> PyResult<()> {
        let entry_value: Value = serde_json::from_str(&data_owned)
            .map_err(|e| PyIOError::new_err(format!("Failed to parse entry data: {}", e)))?;

        if let Some(parent) = Path::new(&path_owned).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut index_data: serde_json::Map<String, Value> = match fs::read_to_string(&path_owned)
        {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => serde_json::Map::new(),
        };

        index_data.insert(entry_owned, entry_value);

        let serialized = serde_json::to_string(&Value::Object(index_data))
            .map_err(|e| PyIOError::new_err(format!("Failed to serialize index: {}", e)))?;

        fs::write(&path_owned, serialized)
            .map_err(|e| PyIOError::new_err(format!("Failed to write index: {}", e)))?;

        Ok(())
    })
}

#[pyfunction]
pub fn delete_index_entry(py: Python<'_>, path: &str, entry_name: &str) -> PyResult<bool> {
    let path_owned = path.to_owned();
    let entry_owned = entry_name.to_owned();

    py.detach(move || -> PyResult<bool> {
        let content = match fs::read_to_string(&path_owned) {
            Ok(c) => c,
            Err(_) => return Ok(false),
        };

        let mut index_data: serde_json::Map<String, Value> =
            match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };

        if index_data.remove(&entry_owned).is_none() {
            return Ok(false);
        }

        if index_data.is_empty() {
            let _ = fs::remove_file(&path_owned);
            return Ok(true);
        }

        let serialized = serde_json::to_string(&Value::Object(index_data))
            .map_err(|e| PyIOError::new_err(format!("Failed to serialize index: {}", e)))?;

        fs::write(&path_owned, serialized)
            .map_err(|e| PyIOError::new_err(format!("Failed to write index: {}", e)))?;

        Ok(false)
    })
}

#[pyfunction]
pub fn check_bucket_contents(
    py: Python<'_>,
    bucket_path: &str,
    version_roots: Vec<String>,
    multipart_roots: Vec<String>,
) -> PyResult<(bool, bool, bool)> {
    let bucket_owned = bucket_path.to_owned();

    py.detach(move || -> PyResult<(bool, bool, bool)> {
        let mut has_objects = false;
        let bucket_p = Path::new(&bucket_owned);
        if bucket_p.is_dir() {
            let mut stack = vec![bucket_p.to_path_buf()];
            'obj_scan: while let Some(current) = stack.pop() {
                let is_root = current == bucket_p;
                let entries = match fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry_result in entries {
                    let entry = match entry_result {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if is_root {
                        if let Some(name) = entry.file_name().to_str() {
                            if INTERNAL_FOLDERS.contains(&name) {
                                continue;
                            }
                        }
                    }
                    if ft.is_file() && !ft.is_symlink() {
                        has_objects = true;
                        break 'obj_scan;
                    }
                    if ft.is_dir() && !ft.is_symlink() {
                        stack.push(entry.path());
                    }
                }
            }
        }

        let mut has_versions = false;
        for root in &version_roots {
            if has_versions {
                break;
            }
            has_versions = has_any_file(root);
        }

        let mut has_multipart = false;
        for root in &multipart_roots {
            if has_multipart {
                break;
            }
            has_multipart = has_any_file(root);
        }

        Ok((has_objects, has_versions, has_multipart))
    })
}

#[pyfunction]
pub fn shallow_scan(
    py: Python<'_>,
    target_dir: &str,
    prefix: &str,
    meta_cache_json: &str,
) -> PyResult<Py<PyAny>> {
    let target_owned = target_dir.to_owned();
    let prefix_owned = prefix.to_owned();
    let cache_owned = meta_cache_json.to_owned();

    let result: (
        Vec<(String, u64, f64, Option<String>)>,
        Vec<String>,
        Vec<(String, bool)>,
    ) = py.detach(move || -> PyResult<(
        Vec<(String, u64, f64, Option<String>)>,
        Vec<String>,
        Vec<(String, bool)>,
    )> {
        let meta_cache: HashMap<String, String> =
            serde_json::from_str(&cache_owned).unwrap_or_default();

        let mut files: Vec<(String, u64, f64, Option<String>)> = Vec::new();
        let mut dirs: Vec<String> = Vec::new();

        let entries = match fs::read_dir(&target_owned) {
            Ok(e) => e,
            Err(_) => return Ok((files, dirs, Vec::new())),
        };

        for entry_result in entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if INTERNAL_FOLDERS.contains(&name.as_str()) {
                continue;
            }
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() && !ft.is_symlink() {
                let cp = format!("{}{}/", prefix_owned, name);
                dirs.push(cp);
            } else if ft.is_file() && !ft.is_symlink() {
                let key = format!("{}{}", prefix_owned, name);
                let md = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let size = md.len();
                let mtime = md
                    .modified()
                    .map(system_time_to_epoch)
                    .unwrap_or(0.0);
                let etag = meta_cache.get(&key).cloned();
                files.push((key, size, mtime, etag));
            }
        }

        files.sort_by(|a, b| a.0.cmp(&b.0));
        dirs.sort();

        let mut merged: Vec<(String, bool)> = Vec::with_capacity(files.len() + dirs.len());
        let mut fi = 0;
        let mut di = 0;
        while fi < files.len() && di < dirs.len() {
            if files[fi].0 <= dirs[di] {
                merged.push((files[fi].0.clone(), false));
                fi += 1;
            } else {
                merged.push((dirs[di].clone(), true));
                di += 1;
            }
        }
        while fi < files.len() {
            merged.push((files[fi].0.clone(), false));
            fi += 1;
        }
        while di < dirs.len() {
            merged.push((dirs[di].clone(), true));
            di += 1;
        }

        Ok((files, dirs, merged))
    })?;

    let (files, dirs, merged) = result;

    let dict = PyDict::new(py);

    let files_list = PyList::empty(py);
    for (key, size, mtime, etag) in &files {
        let etag_py: Py<PyAny> = match etag {
            Some(e) => PyString::new(py, e).into_any().unbind(),
            None => py.None(),
        };
        let tuple = PyTuple::new(py, &[
            PyString::new(py, key).into_any().unbind(),
            size.into_pyobject(py)?.into_any().unbind(),
            mtime.into_pyobject(py)?.into_any().unbind(),
            etag_py,
        ])?;
        files_list.append(tuple)?;
    }
    dict.set_item("files", files_list)?;

    let dirs_list = PyList::empty(py);
    for d in &dirs {
        dirs_list.append(PyString::new(py, d))?;
    }
    dict.set_item("dirs", dirs_list)?;

    let merged_list = PyList::empty(py);
    for (key, is_dir) in &merged {
        let bool_obj: Py<PyAny> = if *is_dir {
            true.into_pyobject(py)?.to_owned().into_any().unbind()
        } else {
            false.into_pyobject(py)?.to_owned().into_any().unbind()
        };
        let tuple = PyTuple::new(py, &[
            PyString::new(py, key).into_any().unbind(),
            bool_obj,
        ])?;
        merged_list.append(tuple)?;
    }
    dict.set_item("merged_keys", merged_list)?;

    Ok(dict.into_any().unbind())
}

#[pyfunction]
pub fn bucket_stats_scan(
    py: Python<'_>,
    bucket_path: &str,
    versions_root: &str,
) -> PyResult<(u64, u64, u64, u64)> {
    let bucket_owned = bucket_path.to_owned();
    let versions_owned = versions_root.to_owned();

    py.detach(move || -> PyResult<(u64, u64, u64, u64)> {
        let mut object_count: u64 = 0;
        let mut total_bytes: u64 = 0;

        let bucket_p = Path::new(&bucket_owned);
        if bucket_p.is_dir() {
            let mut stack = vec![bucket_p.to_path_buf()];
            while let Some(current) = stack.pop() {
                let is_root = current == bucket_p;
                let entries = match fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry_result in entries {
                    let entry = match entry_result {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    if is_root {
                        if let Some(name) = entry.file_name().to_str() {
                            if INTERNAL_FOLDERS.contains(&name) {
                                continue;
                            }
                        }
                    }
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() && !ft.is_symlink() {
                        stack.push(entry.path());
                    } else if ft.is_file() && !ft.is_symlink() {
                        object_count += 1;
                        if let Ok(md) = entry.metadata() {
                            total_bytes += md.len();
                        }
                    }
                }
            }
        }

        let mut version_count: u64 = 0;
        let mut version_bytes: u64 = 0;

        let versions_p = Path::new(&versions_owned);
        if versions_p.is_dir() {
            let mut stack = vec![versions_p.to_path_buf()];
            while let Some(current) = stack.pop() {
                let entries = match fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry_result in entries {
                    let entry = match entry_result {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() && !ft.is_symlink() {
                        stack.push(entry.path());
                    } else if ft.is_file() && !ft.is_symlink() {
                        if let Some(name) = entry.file_name().to_str() {
                            if name.ends_with(".bin") {
                                version_count += 1;
                                if let Ok(md) = entry.metadata() {
                                    version_bytes += md.len();
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((object_count, total_bytes, version_count, version_bytes))
    })
}

#[pyfunction]
#[pyo3(signature = (bucket_path, search_root, query, limit))]
pub fn search_objects_scan(
    py: Python<'_>,
    bucket_path: &str,
    search_root: &str,
    query: &str,
    limit: usize,
) -> PyResult<Py<PyAny>> {
    let bucket_owned = bucket_path.to_owned();
    let search_owned = search_root.to_owned();
    let query_owned = query.to_owned();

    let result: (Vec<(String, u64, f64)>, bool) = py.detach(
        move || -> PyResult<(Vec<(String, u64, f64)>, bool)> {
            let query_lower = query_owned.to_lowercase();
            let bucket_len = bucket_owned.len() + 1;
            let scan_limit = limit * 4;
            let mut matched: usize = 0;
            let mut results: Vec<(String, u64, f64)> = Vec::new();

            let search_p = Path::new(&search_owned);
            if !search_p.is_dir() {
                return Ok((results, false));
            }

            let bucket_p = Path::new(&bucket_owned);
            let mut stack = vec![search_p.to_path_buf()];

            'scan: while let Some(current) = stack.pop() {
                let is_bucket_root = current == bucket_p;
                let entries = match fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry_result in entries {
                    let entry = match entry_result {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    if is_bucket_root {
                        if let Some(name) = entry.file_name().to_str() {
                            if INTERNAL_FOLDERS.contains(&name) {
                                continue;
                            }
                        }
                    }
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() && !ft.is_symlink() {
                        stack.push(entry.path());
                    } else if ft.is_file() && !ft.is_symlink() {
                        let full_path = entry.path();
                        let full_str = full_path.to_string_lossy();
                        if full_str.len() <= bucket_len {
                            continue;
                        }
                        let key = full_str[bucket_len..].replace('\\', "/");
                        if key.to_lowercase().contains(&query_lower) {
                            if let Ok(md) = entry.metadata() {
                                let size = md.len();
                                let mtime = md
                                    .modified()
                                    .map(system_time_to_epoch)
                                    .unwrap_or(0.0);
                                results.push((key, size, mtime));
                                matched += 1;
                            }
                        }
                        if matched >= scan_limit {
                            break 'scan;
                        }
                    }
                }
            }

            results.sort_by(|a, b| a.0.cmp(&b.0));
            let truncated = results.len() > limit;
            results.truncate(limit);

            Ok((results, truncated))
        },
    )?;

    let (results, truncated) = result;

    let dict = PyDict::new(py);

    let results_list = PyList::empty(py);
    for (key, size, mtime) in &results {
        let tuple = PyTuple::new(py, &[
            PyString::new(py, key).into_any().unbind(),
            size.into_pyobject(py)?.into_any().unbind(),
            mtime.into_pyobject(py)?.into_any().unbind(),
        ])?;
        results_list.append(tuple)?;
    }
    dict.set_item("results", results_list)?;
    dict.set_item("truncated", truncated)?;

    Ok(dict.into_any().unbind())
}

#[pyfunction]
pub fn build_object_cache(
    py: Python<'_>,
    bucket_path: &str,
    meta_root: &str,
    etag_index_path: &str,
) -> PyResult<Py<PyAny>> {
    let bucket_owned = bucket_path.to_owned();
    let meta_owned = meta_root.to_owned();
    let index_path_owned = etag_index_path.to_owned();

    let result: (HashMap<String, String>, Vec<(String, u64, f64, Option<String>)>, bool) =
        py.detach(move || -> PyResult<(
            HashMap<String, String>,
            Vec<(String, u64, f64, Option<String>)>,
            bool,
        )> {
            let mut meta_cache: HashMap<String, String> = HashMap::new();
            let mut index_mtime: f64 = 0.0;
            let mut etag_cache_changed = false;

            let index_p = Path::new(&index_path_owned);
            if index_p.is_file() {
                if let Ok(md) = fs::metadata(&index_path_owned) {
                    index_mtime = md
                        .modified()
                        .map(system_time_to_epoch)
                        .unwrap_or(0.0);
                }
                if let Ok(content) = fs::read_to_string(&index_path_owned) {
                    if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(&content) {
                        meta_cache = parsed;
                    }
                }
            }

            let meta_p = Path::new(&meta_owned);
            let mut needs_rebuild = false;

            if meta_p.is_dir() && index_mtime > 0.0 {
                fn check_newer(dir: &Path, index_mtime: f64) -> bool {
                    let entries = match fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return false,
                    };
                    for entry_result in entries {
                        let entry = match entry_result {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let ft = match entry.file_type() {
                            Ok(ft) => ft,
                            Err(_) => continue,
                        };
                        if ft.is_dir() && !ft.is_symlink() {
                            if check_newer(&entry.path(), index_mtime) {
                                return true;
                            }
                        } else if ft.is_file() {
                            if let Some(name) = entry.file_name().to_str() {
                                if name.ends_with(".meta.json") || name == "_index.json" {
                                    if let Ok(md) = entry.metadata() {
                                        let mt = md
                                            .modified()
                                            .map(system_time_to_epoch)
                                            .unwrap_or(0.0);
                                        if mt > index_mtime {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    false
                }
                needs_rebuild = check_newer(meta_p, index_mtime);
            } else if meta_cache.is_empty() {
                needs_rebuild = true;
            }

            if needs_rebuild && meta_p.is_dir() {
                let meta_str = meta_owned.clone();
                let meta_len = meta_str.len() + 1;
                let mut index_files: Vec<String> = Vec::new();
                let mut legacy_meta_files: Vec<(String, String)> = Vec::new();

                fn collect_meta(
                    dir: &Path,
                    meta_len: usize,
                    index_files: &mut Vec<String>,
                    legacy_meta_files: &mut Vec<(String, String)>,
                ) {
                    let entries = match fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    for entry_result in entries {
                        let entry = match entry_result {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let ft = match entry.file_type() {
                            Ok(ft) => ft,
                            Err(_) => continue,
                        };
                        if ft.is_dir() && !ft.is_symlink() {
                            collect_meta(&entry.path(), meta_len, index_files, legacy_meta_files);
                        } else if ft.is_file() {
                            if let Some(name) = entry.file_name().to_str() {
                                let full = entry.path().to_string_lossy().to_string();
                                if name == "_index.json" {
                                    index_files.push(full);
                                } else if name.ends_with(".meta.json") {
                                    if full.len() > meta_len {
                                        let rel = &full[meta_len..];
                                        let key = if rel.len() > 10 {
                                            rel[..rel.len() - 10].replace('\\', "/")
                                        } else {
                                            continue;
                                        };
                                        legacy_meta_files.push((key, full));
                                    }
                                }
                            }
                        }
                    }
                }

                collect_meta(
                    meta_p,
                    meta_len,
                    &mut index_files,
                    &mut legacy_meta_files,
                );

                meta_cache.clear();

                for idx_path in &index_files {
                    if let Ok(content) = fs::read_to_string(idx_path) {
                        if let Ok(idx_data) = serde_json::from_str::<HashMap<String, Value>>(&content) {
                            let rel_dir = if idx_path.len() > meta_len {
                                let r = &idx_path[meta_len..];
                                r.replace('\\', "/")
                            } else {
                                String::new()
                            };
                            let dir_prefix = if rel_dir.ends_with("/_index.json") {
                                &rel_dir[..rel_dir.len() - "/_index.json".len()]
                            } else {
                                ""
                            };
                            for (entry_name, entry_data) in &idx_data {
                                let key = if dir_prefix.is_empty() {
                                    entry_name.clone()
                                } else {
                                    format!("{}/{}", dir_prefix, entry_name)
                                };
                                if let Some(meta_obj) = entry_data.get("metadata") {
                                    if let Some(etag) = meta_obj.get("__etag__") {
                                        if let Some(etag_str) = etag.as_str() {
                                            meta_cache.insert(key, etag_str.to_owned());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                for (key, path) in &legacy_meta_files {
                    if meta_cache.contains_key(key) {
                        continue;
                    }
                    if let Ok(content) = fs::read(path) {
                        if let Some(etag) = extract_etag_from_meta_bytes(&content) {
                            meta_cache.insert(key.clone(), etag);
                        }
                    }
                }

                etag_cache_changed = true;
            }

            let bucket_p = Path::new(&bucket_owned);
            let bucket_len = bucket_owned.len() + 1;
            let mut objects: Vec<(String, u64, f64, Option<String>)> = Vec::new();

            if bucket_p.is_dir() {
                let mut stack = vec![bucket_p.to_path_buf()];
                while let Some(current) = stack.pop() {
                    let entries = match fs::read_dir(&current) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    for entry_result in entries {
                        let entry = match entry_result {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let ft = match entry.file_type() {
                            Ok(ft) => ft,
                            Err(_) => continue,
                        };
                        if ft.is_dir() && !ft.is_symlink() {
                            let full = entry.path();
                            let full_str = full.to_string_lossy();
                            if full_str.len() > bucket_len {
                                let first_part: &str = if let Some(sep_pos) =
                                    full_str[bucket_len..].find(|c: char| c == '\\' || c == '/')
                                {
                                    &full_str[bucket_len..bucket_len + sep_pos]
                                } else {
                                    &full_str[bucket_len..]
                                };
                                if INTERNAL_FOLDERS.contains(&first_part) {
                                    continue;
                                }
                            } else if let Some(name) = entry.file_name().to_str() {
                                if INTERNAL_FOLDERS.contains(&name) {
                                    continue;
                                }
                            }
                            stack.push(full);
                        } else if ft.is_file() && !ft.is_symlink() {
                            let full = entry.path();
                            let full_str = full.to_string_lossy();
                            if full_str.len() <= bucket_len {
                                continue;
                            }
                            let rel = &full_str[bucket_len..];
                            let first_part: &str =
                                if let Some(sep_pos) = rel.find(|c: char| c == '\\' || c == '/') {
                                    &rel[..sep_pos]
                                } else {
                                    rel
                                };
                            if INTERNAL_FOLDERS.contains(&first_part) {
                                continue;
                            }
                            let key = rel.replace('\\', "/");
                            if let Ok(md) = entry.metadata() {
                                let size = md.len();
                                let mtime = md
                                    .modified()
                                    .map(system_time_to_epoch)
                                    .unwrap_or(0.0);
                                let etag = meta_cache.get(&key).cloned();
                                objects.push((key, size, mtime, etag));
                            }
                        }
                    }
                }
            }

            Ok((meta_cache, objects, etag_cache_changed))
        })?;

    let (meta_cache, objects, etag_cache_changed) = result;

    let dict = PyDict::new(py);

    let cache_dict = PyDict::new(py);
    for (k, v) in &meta_cache {
        cache_dict.set_item(k, v)?;
    }
    dict.set_item("etag_cache", cache_dict)?;

    let objects_list = PyList::empty(py);
    for (key, size, mtime, etag) in &objects {
        let etag_py: Py<PyAny> = match etag {
            Some(e) => PyString::new(py, e).into_any().unbind(),
            None => py.None(),
        };
        let tuple = PyTuple::new(py, &[
            PyString::new(py, key).into_any().unbind(),
            size.into_pyobject(py)?.into_any().unbind(),
            mtime.into_pyobject(py)?.into_any().unbind(),
            etag_py,
        ])?;
        objects_list.append(tuple)?;
    }
    dict.set_item("objects", objects_list)?;
    dict.set_item("etag_cache_changed", etag_cache_changed)?;

    Ok(dict.into_any().unbind())
}
