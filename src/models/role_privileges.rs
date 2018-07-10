

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct RolePrivileges {
  #[serde(rename = "privileges")]
  privileges: Option<Vec<::models::AuthIdNtokenPrivilegeItem>>,
  /// Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).
  #[serde(rename = "resume")]
  resume: Option<String>
}

