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
pub struct NtpSettings {
  /// NTP settings.
  #[serde(rename = "settings")]
  settings: Option<::models::NtpSettingsSettings>
}

impl NtpSettings {
  pub fn new() -> NtpSettings {
    NtpSettings {
      settings: None
    }
  }

  pub fn set_settings(&mut self, settings: ::models::NtpSettingsSettings) {
    self.settings = Some(settings);
  }

  pub fn with_settings(mut self, settings: ::models::NtpSettingsSettings) -> NtpSettings {
    self.settings = Some(settings);
    self
  }

  pub fn settings(&self) -> Option<&::models::NtpSettingsSettings> {
    self.settings.as_ref()
  }

  pub fn reset_settings(&mut self) {
    self.settings = None;
  }

}



