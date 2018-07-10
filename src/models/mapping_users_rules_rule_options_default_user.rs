

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct MappingUsersRulesRuleOptionsDefaultUser {
  #[serde(rename = "domain")]
  domain: Option<String>,
  #[serde(rename = "user")]
  user: String
}

