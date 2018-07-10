

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SmbLogLevelFilters {
  #[serde(rename = "filters")]
  filters: Option<Vec<::models::SmbLogLevelFiltersFilter>>
}

