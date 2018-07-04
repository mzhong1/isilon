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
pub struct SettingsAccessTimeSettings {
  /// Enable access time tracking.
  #[serde(rename = "enabled")]
  enabled: bool,
  /// Access time tracked in seconds for each cluster file if enabled.
  #[serde(rename = "precision")]
  precision: i32
}

impl SettingsAccessTimeSettings {
  pub fn new(enabled: bool, precision: i32) -> SettingsAccessTimeSettings {
    SettingsAccessTimeSettings {
      enabled: enabled,
      precision: precision
    }
  }

  pub fn set_enabled(&mut self, enabled: bool) {
    self.enabled = enabled;
  }

  pub fn with_enabled(mut self, enabled: bool) -> SettingsAccessTimeSettings {
    self.enabled = enabled;
    self
  }

  pub fn enabled(&self) -> &bool {
    &self.enabled
  }


  pub fn set_precision(&mut self, precision: i32) {
    self.precision = precision;
  }

  pub fn with_precision(mut self, precision: i32) -> SettingsAccessTimeSettings {
    self.precision = precision;
    self
  }

  pub fn precision(&self) -> &i32 {
    &self.precision
  }


}



