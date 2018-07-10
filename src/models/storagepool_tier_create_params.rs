

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct StoragepoolTierCreateParams {
  /// The names or IDs of the tier's children.
  #[serde(rename = "children")]
  children: Option<Vec<String>>,
  /// The tier name.
  #[serde(rename = "name")]
  name: String
}

