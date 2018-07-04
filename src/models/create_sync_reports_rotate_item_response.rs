/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// CreateSyncReportsRotateItemResponse : Force rotation of reports.

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSyncReportsRotateItemResponse {
  /// A message about the status of the task.
  #[serde(rename = "message")]
  message: String
}

impl CreateSyncReportsRotateItemResponse {
  /// Force rotation of reports.
  pub fn new(message: String) -> CreateSyncReportsRotateItemResponse {
    CreateSyncReportsRotateItemResponse {
      message: message
    }
  }

  pub fn set_message(&mut self, message: String) {
    self.message = message;
  }

  pub fn with_message(mut self, message: String) -> CreateSyncReportsRotateItemResponse {
    self.message = message;
    self
  }

  pub fn message(&self) -> &String {
    &self.message
  }


}



