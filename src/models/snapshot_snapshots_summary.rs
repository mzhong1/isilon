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
pub struct SnapshotSnapshotsSummary {
  /// 
  #[serde(rename = "summary")]
  summary: Option<::models::SnapshotSnapshotsSummarySummary>
}

impl SnapshotSnapshotsSummary {
  pub fn new() -> SnapshotSnapshotsSummary {
    SnapshotSnapshotsSummary {
      summary: None
    }
  }

  pub fn set_summary(&mut self, summary: ::models::SnapshotSnapshotsSummarySummary) {
    self.summary = Some(summary);
  }

  pub fn with_summary(mut self, summary: ::models::SnapshotSnapshotsSummarySummary) -> SnapshotSnapshotsSummary {
    self.summary = Some(summary);
    self
  }

  pub fn summary(&self) -> Option<&::models::SnapshotSnapshotsSummarySummary> {
    self.summary.as_ref()
  }

  pub fn reset_summary(&mut self) {
    self.summary = None;
  }

}



