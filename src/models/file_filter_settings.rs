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
pub struct FileFilterSettings {
  /// 
  #[serde(rename = "settings")]
  settings: ::models::FileFilterSettingsSettings
}

impl FileFilterSettings {
  pub fn new(settings: ::models::FileFilterSettingsSettings) -> FileFilterSettings {
    FileFilterSettings {
      settings: settings
    }
  }

  pub fn set_settings(&mut self, settings: ::models::FileFilterSettingsSettings) {
    self.settings = settings;
  }

  pub fn with_settings(mut self, settings: ::models::FileFilterSettingsSettings) -> FileFilterSettings {
    self.settings = settings;
    self
  }

  pub fn settings(&self) -> &::models::FileFilterSettingsSettings {
    &self.settings
  }


}



