/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvidersNis {
  #[serde(rename = "nis")]
  nis: Option<Vec<::models::ProvidersNisNisItem>>
}

impl ProvidersNis {
  pub fn new() -> ProvidersNis {
    ProvidersNis {
      nis: None
    }
  }

  pub fn set_nis(&mut self, nis: Vec<::models::ProvidersNisNisItem>) {
    self.nis = Some(nis);
  }

  pub fn with_nis(mut self, nis: Vec<::models::ProvidersNisNisItem>) -> ProvidersNis {
    self.nis = Some(nis);
    self
  }

  pub fn nis(&self) -> Option<&Vec<::models::ProvidersNisNisItem>> {
    self.nis.as_ref()
  }

  pub fn reset_nis(&mut self) {
    self.nis = None;
  }

}



