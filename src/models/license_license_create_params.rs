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
pub struct LicenseLicenseCreateParams {
  /// A list of evaluation licenses to enable on the cluster.
  #[serde(rename = "evaluation")]
  evaluation: Option<Vec<String>>,
  /// License file string content. The license file is obtained from EMC's SLC web portal. Do not use with the license_file_path option.
  #[serde(rename = "license_file_content")]
  license_file_content: Option<String>,
  /// Path to new license file, must be under /ifs. The license file is obtained from EMC's SLC web portal. Do not include the path when only enabling evaluation licenses. Do not use with the license_file_content option.
  #[serde(rename = "license_file_path")]
  license_file_path: Option<String>
}

impl LicenseLicenseCreateParams {
  pub fn new() -> LicenseLicenseCreateParams {
    LicenseLicenseCreateParams {
      evaluation: None,
      license_file_content: None,
      license_file_path: None
    }
  }

  pub fn set_evaluation(&mut self, evaluation: Vec<String>) {
    self.evaluation = Some(evaluation);
  }

  pub fn with_evaluation(mut self, evaluation: Vec<String>) -> LicenseLicenseCreateParams {
    self.evaluation = Some(evaluation);
    self
  }

  pub fn evaluation(&self) -> Option<&Vec<String>> {
    self.evaluation.as_ref()
  }

  pub fn reset_evaluation(&mut self) {
    self.evaluation = None;
  }

  pub fn set_license_file_content(&mut self, license_file_content: String) {
    self.license_file_content = Some(license_file_content);
  }

  pub fn with_license_file_content(mut self, license_file_content: String) -> LicenseLicenseCreateParams {
    self.license_file_content = Some(license_file_content);
    self
  }

  pub fn license_file_content(&self) -> Option<&String> {
    self.license_file_content.as_ref()
  }

  pub fn reset_license_file_content(&mut self) {
    self.license_file_content = None;
  }

  pub fn set_license_file_path(&mut self, license_file_path: String) {
    self.license_file_path = Some(license_file_path);
  }

  pub fn with_license_file_path(mut self, license_file_path: String) -> LicenseLicenseCreateParams {
    self.license_file_path = Some(license_file_path);
    self
  }

  pub fn license_file_path(&self) -> Option<&String> {
    self.license_file_path.as_ref()
  }

  pub fn reset_license_file_path(&mut self) {
    self.license_file_path = None;
  }

}



