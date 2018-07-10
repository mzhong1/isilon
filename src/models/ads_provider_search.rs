

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct AdsProviderSearch {
  #[serde(rename = "objects")]
  objects: Option<Vec<::models::AdsProviderSearchObject>>,
  /// Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).
  #[serde(rename = "resume")]
  resume: Option<String>
}

