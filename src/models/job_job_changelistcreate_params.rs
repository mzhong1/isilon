

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JobJobChangelistcreateParams {
  /// Newer snapshot ID.
  #[serde(rename = "newer_snapid")]
  newer_snapid: i32,
  /// Older snapshot ID.
  #[serde(rename = "older_snapid")]
  older_snapid: i32,
  /// Whether to retain the replication record after a changelist is created. Retaining a replication record allows a changelist to be recreated later.
  #[serde(rename = "retain_repstate")]
  retain_repstate: Option<bool>
}

