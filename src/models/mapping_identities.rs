

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct MappingIdentities {
  #[serde(rename = "identities")]
  identities: Option<Vec<::models::MappingIdentity>>
}

