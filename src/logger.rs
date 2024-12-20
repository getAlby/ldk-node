// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

pub(crate) use lightning::util::logger::Logger;
pub(crate) use lightning::{log_bytes, log_debug, log_error, log_info, log_trace};

use lightning::util::logger::{Level, Record};

use chrono::Utc;

use std::fs;
use std::io::Write;
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

pub(crate) struct FilesystemLogger {
	log_dir: String,
	level: Level,
}

impl FilesystemLogger {
	pub(crate) fn new(log_dir: String, level: Level) -> Result<Self, ()> {
		fs::create_dir_all(&log_dir).expect("Failed to create log parent directory");

		Ok(Self { log_dir, level })
	}

	fn make_log_file_name() -> String {
		format!("ldk_node_{}.log", chrono::offset::Local::now().format("%Y_%m_%d"))
	}

	fn make_log_file_symlink<D: AsRef<Path>, F: AsRef<Path>>(
		log_dir: D, log_file_name: F,
	) -> Result<(), ()> {
		#[cfg(not(target_os = "windows"))]
		{
			// Create a symlink to the current log file, with prior cleanup
			let log_file_symlink = log_dir.as_ref().join("ldk_node_latest.log");
			if log_file_symlink.as_path().is_symlink() {
				fs::remove_file(&log_file_symlink)
					.map_err(|e| eprintln!("ERROR: Failed to remove log file symlink: {}", e))?;
			}
			symlink(&log_file_name, &log_file_symlink)
				.map_err(|e| eprintln!("ERROR: Failed to create log file symlink: {}", e))?;
		}

		Ok(())
	}

	fn log_file_path(&self) -> PathBuf {
		PathBuf::from(format!("{}/{}", self.log_dir, FilesystemLogger::make_log_file_name()))
	}

	fn open_log_file(&self) -> Result<fs::File, ()> {
		let log_path = self.log_file_path();
		let is_new_file = log_path.try_exists().and_then(|e| Ok(!e)).unwrap_or(false);

		let ret = fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(&log_path)
			.map_err(|e| eprintln!("ERROR: Failed to open log file: {}", e))?;

		if is_new_file {
			// Do not check for errors; in concurrent scenarios, this is not
			// unlikely to fail. The concurrent thread should be able to finish
			// the operation.
			let _ = FilesystemLogger::make_log_file_symlink(
				&self.log_dir,
				log_path.file_name().unwrap(),
			);
		}

		Ok(ret)
	}
}
impl Logger for FilesystemLogger {
	fn log(&self, record: Record) {
		if record.level < self.level {
			return;
		}
		let raw_log = record.args.to_string();
		let log = format!(
			"{} {:<5} [{}:{}] {}\n",
			Utc::now().format("%Y-%m-%d %H:%M:%S"),
			record.level.to_string(),
			record.module_path,
			record.line,
			raw_log
		);
		self.open_log_file()
			.expect("Failed to open log file")
			.write_all(log.as_bytes())
			.expect("Failed to write to log file");
	}
}
