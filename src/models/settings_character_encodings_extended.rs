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
pub struct SettingsCharacterEncodingsExtended {
  /// Current character encoding.
  #[serde(rename = "current-encoding")]
  current_encoding: Option<String>
}

impl SettingsCharacterEncodingsExtended {
  pub fn new() -> SettingsCharacterEncodingsExtended {
    SettingsCharacterEncodingsExtended {
      current_encoding: None
    }
  }

  pub fn set_current_encoding(&mut self, current_encoding: String) {
    self.current_encoding = Some(current_encoding);
  }

  pub fn with_current_encoding(mut self, current_encoding: String) -> SettingsCharacterEncodingsExtended {
    self.current_encoding = Some(current_encoding);
    self
  }

  pub fn current_encoding(&self) -> Option<&String> {
    self.current_encoding.as_ref()
  }

  pub fn reset_current_encoding(&mut self) {
    self.current_encoding = None;
  }

}



