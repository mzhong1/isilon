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
pub struct FsaResultsExtended {
  #[serde(rename = "results")]
  results: Option<Vec<::models::FsaResultExtended>>,
  /// Total number of items available.
  #[serde(rename = "total")]
  total: Option<i32>
}

impl FsaResultsExtended {
  pub fn new() -> FsaResultsExtended {
    FsaResultsExtended {
      results: None,
      total: None
    }
  }

  pub fn set_results(&mut self, results: Vec<::models::FsaResultExtended>) {
    self.results = Some(results);
  }

  pub fn with_results(mut self, results: Vec<::models::FsaResultExtended>) -> FsaResultsExtended {
    self.results = Some(results);
    self
  }

  pub fn results(&self) -> Option<&Vec<::models::FsaResultExtended>> {
    self.results.as_ref()
  }

  pub fn reset_results(&mut self) {
    self.results = None;
  }

  pub fn set_total(&mut self, total: i32) {
    self.total = Some(total);
  }

  pub fn with_total(mut self, total: i32) -> FsaResultsExtended {
    self.total = Some(total);
    self
  }

  pub fn total(&self) -> Option<&i32> {
    self.total.as_ref()
  }

  pub fn reset_total(&mut self) {
    self.total = None;
  }

}



