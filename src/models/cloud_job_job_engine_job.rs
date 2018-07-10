

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudJobJobEngineJob {
  /// ID of the related job engine job
  #[serde(rename = "id")]
  id: Option<i32>,
  /// The state of the related job engine job
  #[serde(rename = "state")]
  state: Option<String>
}

