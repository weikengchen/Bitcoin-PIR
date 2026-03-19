//! Shared utility functions for build_db tools.

/// Format duration in seconds to a human-readable string (e.g., "2h 15m 30s").
pub fn format_duration(secs: f64) -> String {
    if secs.is_infinite() || secs.is_nan() {
        return "calculating...".to_string();
    }

    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format byte count to a human-readable string (e.g., "1.23 GB").
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Read a progress counter (u64) from a file. Returns 0 if the file is missing or unparseable.
pub fn get_progress(path: &str) -> u64 {
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Write a progress counter (u64) to a file.
pub fn save_progress(path: &str, value: u64) {
    if let Err(e) = std::fs::write(path, value.to_string()) {
        eprintln!("Warning: Failed to save progress to {}: {}", path, e);
    }
}
