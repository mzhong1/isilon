

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JobTypesExtended {
  #[serde(rename = "types")]
  types: Option<Vec<::models::JobTypeExtended>>,
  /// Total number of items available.
  #[serde(rename = "total")]
  total: Option<i32>
}

