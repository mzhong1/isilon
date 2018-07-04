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
pub struct NodeDriveconfigNodeAlert {
  /// Send alerts for unknown drive firmware.
  #[serde(rename = "unknown_firmware")]
  unknown_firmware: Option<bool>,
  /// Send alerts for unknown drive model.
  #[serde(rename = "unknown_model")]
  unknown_model: Option<bool>
}

impl NodeDriveconfigNodeAlert {
  pub fn new() -> NodeDriveconfigNodeAlert {
    NodeDriveconfigNodeAlert {
      unknown_firmware: None,
      unknown_model: None
    }
  }

  pub fn set_unknown_firmware(&mut self, unknown_firmware: bool) {
    self.unknown_firmware = Some(unknown_firmware);
  }

  pub fn with_unknown_firmware(mut self, unknown_firmware: bool) -> NodeDriveconfigNodeAlert {
    self.unknown_firmware = Some(unknown_firmware);
    self
  }

  pub fn unknown_firmware(&self) -> Option<&bool> {
    self.unknown_firmware.as_ref()
  }

  pub fn reset_unknown_firmware(&mut self) {
    self.unknown_firmware = None;
  }

  pub fn set_unknown_model(&mut self, unknown_model: bool) {
    self.unknown_model = Some(unknown_model);
  }

  pub fn with_unknown_model(mut self, unknown_model: bool) -> NodeDriveconfigNodeAlert {
    self.unknown_model = Some(unknown_model);
    self
  }

  pub fn unknown_model(&self) -> Option<&bool> {
    self.unknown_model.as_ref()
  }

  pub fn reset_unknown_model(&mut self) {
    self.unknown_model = None;
  }

}



