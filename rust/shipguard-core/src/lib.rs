use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use pyo3::prelude::*;

#[pyfunction]
fn discover_files(target_dir: String, exclude_patterns: Vec<String>) -> PyResult<Vec<String>> {
    let mut overrides_builder = OverrideBuilder::new(&target_dir);
    for pat in exclude_patterns {
        // patterns starting with ! are ignored in OverridesBuilder (meaning they are excluded from the walk)
        // Wait, OverridesBuilder: !pattern means exclude.
        let _ = overrides_builder.add(&format!("!{}", pat));
    }
    let overrides = overrides_builder.build().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid exclude pattern: {}", e))
    })?;

    let mut builder = WalkBuilder::new(&target_dir);
    builder.hidden(false); // We want to parse hidden files if not ignored
    builder.standard_filters(true); // Respect .gitignore, .ignore, etc.
    builder.overrides(overrides);

    let mut files = Vec::new();
    for result in builder.build() {
        if let Ok(entry) = result {
            if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                let path_str = entry.path().to_string_lossy().to_string();
                files.push(path_str);
            }
        }
    }
    
    Ok(files)
}

#[pymodule]
fn shipguard_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(discover_files, m)?)?;
    Ok(())
}
