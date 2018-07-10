

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct NdmpSettingsPreferredIpsPreference {
  #[serde(rename = "data_subnets")]
  data_subnets: Option<Vec<::models::NdmpSettingsPreferredIpDataSubnet>>,
  /// The unique display id, same as scope
  #[serde(rename = "id")]
  id: Option<String>,
  /// Either cluster or a network subnet defined in OneFS.
  #[serde(rename = "scope")]
  scope: Option<String>
}

