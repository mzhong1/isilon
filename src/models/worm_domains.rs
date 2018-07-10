

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct WormDomains {
  #[serde(rename = "domains")]
  domains: Option<Vec<::models::WormDomainExtended>>
}

