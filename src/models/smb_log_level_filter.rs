

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SmbLogLevelFilter {
  /// Array of client IP addresses to filter against.
  #[serde(rename = "ip_addrs")]
  ip_addrs: Option<Vec<String>>,
  /// Logging level of the filter.
  #[serde(rename = "level")]
  level: String,
  /// Array of SMB operations to filter against.
  #[serde(rename = "ops")]
  ops: Option<Vec<String>>
}

