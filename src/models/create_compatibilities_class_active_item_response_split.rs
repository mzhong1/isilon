

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCompatibilitiesClassActiveItemResponseSplit {
  /// The nodepool id that will be split
  #[serde(rename = "id")]
  id: i32,
  /// The nodepool name that will be split
  #[serde(rename = "name")]
  name: String,
  /// A message explaining how the nodepools tier membership will change.
  #[serde(rename = "tier_name")]
  tier_name: String
}

