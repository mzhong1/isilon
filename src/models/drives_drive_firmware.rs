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
pub struct DrivesDriveFirmware {
  /// A list of errors encountered by the individual nodes involved in this request, or an empty list if there were no errors.
  #[serde(rename = "errors")]
  errors: Option<Vec<::models::NodeDrivesPurposelistError>>,
  /// The responses from the individual nodes involved in this request.
  #[serde(rename = "nodes")]
  nodes: Option<Vec<::models::DrivesDriveFirmwareNode>>,
  /// The total number of nodes responding.
  #[serde(rename = "total")]
  total: Option<i32>
}

impl DrivesDriveFirmware {
  pub fn new() -> DrivesDriveFirmware {
    DrivesDriveFirmware {
      errors: None,
      nodes: None,
      total: None
    }
  }

  pub fn set_errors(&mut self, errors: Vec<::models::NodeDrivesPurposelistError>) {
    self.errors = Some(errors);
  }

  pub fn with_errors(mut self, errors: Vec<::models::NodeDrivesPurposelistError>) -> DrivesDriveFirmware {
    self.errors = Some(errors);
    self
  }

  pub fn errors(&self) -> Option<&Vec<::models::NodeDrivesPurposelistError>> {
    self.errors.as_ref()
  }

  pub fn reset_errors(&mut self) {
    self.errors = None;
  }

  pub fn set_nodes(&mut self, nodes: Vec<::models::DrivesDriveFirmwareNode>) {
    self.nodes = Some(nodes);
  }

  pub fn with_nodes(mut self, nodes: Vec<::models::DrivesDriveFirmwareNode>) -> DrivesDriveFirmware {
    self.nodes = Some(nodes);
    self
  }

  pub fn nodes(&self) -> Option<&Vec<::models::DrivesDriveFirmwareNode>> {
    self.nodes.as_ref()
  }

  pub fn reset_nodes(&mut self) {
    self.nodes = None;
  }

  pub fn set_total(&mut self, total: i32) {
    self.total = Some(total);
  }

  pub fn with_total(mut self, total: i32) -> DrivesDriveFirmware {
    self.total = Some(total);
    self
  }

  pub fn total(&self) -> Option<&i32> {
    self.total.as_ref()
  }

  pub fn reset_total(&mut self) {
    self.total = None;
  }

}



