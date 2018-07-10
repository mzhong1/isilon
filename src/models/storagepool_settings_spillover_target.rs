

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct StoragepoolSettingsSpilloverTarget {
  /// Target pool ID if target specified, otherwise null.
  #[serde(rename = "name_or_id")]
  name_or_id: Option<String>,
  /// Type of target pool.
  #[serde(rename = "type")]
  _type: String
}

