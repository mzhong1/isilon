

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JobJobPrepairParams {
  /// Type of permissions; not accepted with mode=clone or mode=inherit.
  #[serde(rename = "mapping_type")]
  mapping_type: Option<String>,
  /// Type of PermissionRepair operation.
  #[serde(rename = "mode")]
  mode: String,
  /// IFS file or directory to use as a template; required with mode=clone and mode=inherit, not accepted with mode=convert.
  #[serde(rename = "template")]
  template: Option<String>,
  /// Authentication zone; not accepted with mode=clone or mode=inherit.
  #[serde(rename = "zone")]
  zone: Option<String>
}

