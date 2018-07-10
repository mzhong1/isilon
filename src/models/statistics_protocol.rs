

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatisticsProtocol {
  /// Abbreviated name of protocol.
  #[serde(rename = "name")]
  name: String,
  /// External protocols are customer facing, internal protocols expose metrics for internal OneFS systems.
  #[serde(rename = "type")]
  _type: String
}

