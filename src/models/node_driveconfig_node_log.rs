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
pub struct NodeDriveconfigNodeLog {
  /// Indicates whether or not to log the drive statistics.
  #[serde(rename = "drive_stats")]
  drive_stats: Option<bool>
}

impl NodeDriveconfigNodeLog {
  pub fn new() -> NodeDriveconfigNodeLog {
    NodeDriveconfigNodeLog {
      drive_stats: None
    }
  }

  pub fn set_drive_stats(&mut self, drive_stats: bool) {
    self.drive_stats = Some(drive_stats);
  }

  pub fn with_drive_stats(mut self, drive_stats: bool) -> NodeDriveconfigNodeLog {
    self.drive_stats = Some(drive_stats);
    self
  }

  pub fn drive_stats(&self) -> Option<&bool> {
    self.drive_stats.as_ref()
  }

  pub fn reset_drive_stats(&mut self) {
    self.drive_stats = None;
  }

}



