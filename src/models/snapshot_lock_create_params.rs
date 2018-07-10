

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotLockCreateParams {
  /// The Unix Epoch time the snapshot lock will expire and be eligible for automatic deletion.
  #[serde(rename = "expires")]
  expires: Option<i32>,
  /// Free form comment.
  #[serde(rename = "comment")]
  comment: Option<String>
}

