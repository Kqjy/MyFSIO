use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use serde_json::Value;
use std::fs;

const MAX_DEPTH: u32 = 64;

fn value_to_py(py: Python<'_>, v: &Value, depth: u32) -> PyResult<Py<PyAny>> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err("JSON nesting too deep"));
    }
    match v {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok((*b).into_pyobject(py)?.to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        Value::String(s) => Ok(PyString::new(py, s).into_any().unbind()),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(value_to_py(py, item, depth + 1)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, val) in map {
                dict.set_item(k, value_to_py(py, val, depth + 1)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

#[pyfunction]
pub fn read_index_entry(
    py: Python<'_>,
    path: &str,
    entry_name: &str,
) -> PyResult<Option<Py<PyAny>>> {
    let path_owned = path.to_owned();
    let entry_owned = entry_name.to_owned();

    let entry: Option<Value> = py.detach(move || -> PyResult<Option<Value>> {
        let content = match fs::read_to_string(&path_owned) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        let parsed: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        match parsed {
            Value::Object(mut map) => Ok(map.remove(&entry_owned)),
            _ => Ok(None),
        }
    })?;

    match entry {
        Some(val) => Ok(Some(value_to_py(py, &val, 0)?)),
        None => Ok(None),
    }
}
