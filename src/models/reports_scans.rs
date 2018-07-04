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
pub struct ReportsScans {
  #[serde(rename = "reports")]
  reports: Option<Vec<::models::ReportsScansReport>>
}

impl ReportsScans {
  pub fn new() -> ReportsScans {
    ReportsScans {
      reports: None
    }
  }

  pub fn set_reports(&mut self, reports: Vec<::models::ReportsScansReport>) {
    self.reports = Some(reports);
  }

  pub fn with_reports(mut self, reports: Vec<::models::ReportsScansReport>) -> ReportsScans {
    self.reports = Some(reports);
    self
  }

  pub fn reports(&self) -> Option<&Vec<::models::ReportsScansReport>> {
    self.reports.as_ref()
  }

  pub fn reset_reports(&mut self) {
    self.reports = None;
  }

}



