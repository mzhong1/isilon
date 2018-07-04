/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct AntivirusSettingsSettings {
  /// Allow access when scanning fails.
  #[serde(rename = "fail_open")]
  fail_open: Option<bool>,
  /// Glob patterns for leaf filenames.
  #[serde(rename = "glob_filters")]
  glob_filters: Option<Vec<String>>,
  /// Enable glob filters.
  #[serde(rename = "glob_filters_enabled")]
  glob_filters_enabled: Option<bool>,
  /// If true, only scan files matching a glob filter. If false, only scan files that don't match a glob filter.
  #[serde(rename = "glob_filters_include")]
  glob_filters_include: Option<bool>,
  /// Paths to include in realtime scans.
  #[serde(rename = "path_prefixes")]
  path_prefixes: Option<Vec<String>>,
  /// Try to quarantine files when threats are found.
  #[serde(rename = "quarantine")]
  quarantine: Option<bool>,
  /// Try to repair files when threats are found.
  #[serde(rename = "repair")]
  repair: Option<bool>,
  /// Amount of time in seconds until old reporting data is purged.
  #[serde(rename = "report_expiry")]
  report_expiry: Option<i32>,
  /// Scan files when apps close them.
  #[serde(rename = "scan_on_close")]
  scan_on_close: Option<bool>,
  /// Scan files on access.
  #[serde(rename = "scan_on_open")]
  scan_on_open: Option<bool>,
  /// Skip scanning files larger than this.
  #[serde(rename = "scan_size_maximum")]
  scan_size_maximum: Option<i32>,
  /// Whether the antivirus service is enabled.
  #[serde(rename = "service")]
  service: Option<bool>,
  /// Try to truncate files when threats are found.
  #[serde(rename = "truncate")]
  truncate: Option<bool>
}

impl AntivirusSettingsSettings {
  pub fn new() -> AntivirusSettingsSettings {
    AntivirusSettingsSettings {
      fail_open: None,
      glob_filters: None,
      glob_filters_enabled: None,
      glob_filters_include: None,
      path_prefixes: None,
      quarantine: None,
      repair: None,
      report_expiry: None,
      scan_on_close: None,
      scan_on_open: None,
      scan_size_maximum: None,
      service: None,
      truncate: None
    }
  }

  pub fn set_fail_open(&mut self, fail_open: bool) {
    self.fail_open = Some(fail_open);
  }

  pub fn with_fail_open(mut self, fail_open: bool) -> AntivirusSettingsSettings {
    self.fail_open = Some(fail_open);
    self
  }

  pub fn fail_open(&self) -> Option<&bool> {
    self.fail_open.as_ref()
  }

  pub fn reset_fail_open(&mut self) {
    self.fail_open = None;
  }

  pub fn set_glob_filters(&mut self, glob_filters: Vec<String>) {
    self.glob_filters = Some(glob_filters);
  }

  pub fn with_glob_filters(mut self, glob_filters: Vec<String>) -> AntivirusSettingsSettings {
    self.glob_filters = Some(glob_filters);
    self
  }

  pub fn glob_filters(&self) -> Option<&Vec<String>> {
    self.glob_filters.as_ref()
  }

  pub fn reset_glob_filters(&mut self) {
    self.glob_filters = None;
  }

  pub fn set_glob_filters_enabled(&mut self, glob_filters_enabled: bool) {
    self.glob_filters_enabled = Some(glob_filters_enabled);
  }

  pub fn with_glob_filters_enabled(mut self, glob_filters_enabled: bool) -> AntivirusSettingsSettings {
    self.glob_filters_enabled = Some(glob_filters_enabled);
    self
  }

  pub fn glob_filters_enabled(&self) -> Option<&bool> {
    self.glob_filters_enabled.as_ref()
  }

  pub fn reset_glob_filters_enabled(&mut self) {
    self.glob_filters_enabled = None;
  }

  pub fn set_glob_filters_include(&mut self, glob_filters_include: bool) {
    self.glob_filters_include = Some(glob_filters_include);
  }

  pub fn with_glob_filters_include(mut self, glob_filters_include: bool) -> AntivirusSettingsSettings {
    self.glob_filters_include = Some(glob_filters_include);
    self
  }

  pub fn glob_filters_include(&self) -> Option<&bool> {
    self.glob_filters_include.as_ref()
  }

  pub fn reset_glob_filters_include(&mut self) {
    self.glob_filters_include = None;
  }

  pub fn set_path_prefixes(&mut self, path_prefixes: Vec<String>) {
    self.path_prefixes = Some(path_prefixes);
  }

  pub fn with_path_prefixes(mut self, path_prefixes: Vec<String>) -> AntivirusSettingsSettings {
    self.path_prefixes = Some(path_prefixes);
    self
  }

  pub fn path_prefixes(&self) -> Option<&Vec<String>> {
    self.path_prefixes.as_ref()
  }

  pub fn reset_path_prefixes(&mut self) {
    self.path_prefixes = None;
  }

  pub fn set_quarantine(&mut self, quarantine: bool) {
    self.quarantine = Some(quarantine);
  }

  pub fn with_quarantine(mut self, quarantine: bool) -> AntivirusSettingsSettings {
    self.quarantine = Some(quarantine);
    self
  }

  pub fn quarantine(&self) -> Option<&bool> {
    self.quarantine.as_ref()
  }

  pub fn reset_quarantine(&mut self) {
    self.quarantine = None;
  }

  pub fn set_repair(&mut self, repair: bool) {
    self.repair = Some(repair);
  }

  pub fn with_repair(mut self, repair: bool) -> AntivirusSettingsSettings {
    self.repair = Some(repair);
    self
  }

  pub fn repair(&self) -> Option<&bool> {
    self.repair.as_ref()
  }

  pub fn reset_repair(&mut self) {
    self.repair = None;
  }

  pub fn set_report_expiry(&mut self, report_expiry: i32) {
    self.report_expiry = Some(report_expiry);
  }

  pub fn with_report_expiry(mut self, report_expiry: i32) -> AntivirusSettingsSettings {
    self.report_expiry = Some(report_expiry);
    self
  }

  pub fn report_expiry(&self) -> Option<&i32> {
    self.report_expiry.as_ref()
  }

  pub fn reset_report_expiry(&mut self) {
    self.report_expiry = None;
  }

  pub fn set_scan_on_close(&mut self, scan_on_close: bool) {
    self.scan_on_close = Some(scan_on_close);
  }

  pub fn with_scan_on_close(mut self, scan_on_close: bool) -> AntivirusSettingsSettings {
    self.scan_on_close = Some(scan_on_close);
    self
  }

  pub fn scan_on_close(&self) -> Option<&bool> {
    self.scan_on_close.as_ref()
  }

  pub fn reset_scan_on_close(&mut self) {
    self.scan_on_close = None;
  }

  pub fn set_scan_on_open(&mut self, scan_on_open: bool) {
    self.scan_on_open = Some(scan_on_open);
  }

  pub fn with_scan_on_open(mut self, scan_on_open: bool) -> AntivirusSettingsSettings {
    self.scan_on_open = Some(scan_on_open);
    self
  }

  pub fn scan_on_open(&self) -> Option<&bool> {
    self.scan_on_open.as_ref()
  }

  pub fn reset_scan_on_open(&mut self) {
    self.scan_on_open = None;
  }

  pub fn set_scan_size_maximum(&mut self, scan_size_maximum: i32) {
    self.scan_size_maximum = Some(scan_size_maximum);
  }

  pub fn with_scan_size_maximum(mut self, scan_size_maximum: i32) -> AntivirusSettingsSettings {
    self.scan_size_maximum = Some(scan_size_maximum);
    self
  }

  pub fn scan_size_maximum(&self) -> Option<&i32> {
    self.scan_size_maximum.as_ref()
  }

  pub fn reset_scan_size_maximum(&mut self) {
    self.scan_size_maximum = None;
  }

  pub fn set_service(&mut self, service: bool) {
    self.service = Some(service);
  }

  pub fn with_service(mut self, service: bool) -> AntivirusSettingsSettings {
    self.service = Some(service);
    self
  }

  pub fn service(&self) -> Option<&bool> {
    self.service.as_ref()
  }

  pub fn reset_service(&mut self) {
    self.service = None;
  }

  pub fn set_truncate(&mut self, truncate: bool) {
    self.truncate = Some(truncate);
  }

  pub fn with_truncate(mut self, truncate: bool) -> AntivirusSettingsSettings {
    self.truncate = Some(truncate);
    self
  }

  pub fn truncate(&self) -> Option<&bool> {
    self.truncate.as_ref()
  }

  pub fn reset_truncate(&mut self) {
    self.truncate = None;
  }

}



