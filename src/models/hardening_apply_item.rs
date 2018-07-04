/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// HardeningApplyItem : Apply hardening on the cluster.

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningApplyItem {
  /// Hardening profile.
  #[serde(rename = "profile")]
  profile: Option<String>,
  /// Option to only generate and display a report on current cluster configuration with respect to the expected configuation required to apply hardening. If his option is set to true, hardening is not applied after the report is displayed. By default, this option is false.
  #[serde(rename = "report")]
  report: Option<bool>
}

impl HardeningApplyItem {
  /// Apply hardening on the cluster.
  pub fn new() -> HardeningApplyItem {
    HardeningApplyItem {
      profile: None,
      report: None
    }
  }

  pub fn set_profile(&mut self, profile: String) {
    self.profile = Some(profile);
  }

  pub fn with_profile(mut self, profile: String) -> HardeningApplyItem {
    self.profile = Some(profile);
    self
  }

  pub fn profile(&self) -> Option<&String> {
    self.profile.as_ref()
  }

  pub fn reset_profile(&mut self) {
    self.profile = None;
  }

  pub fn set_report(&mut self, report: bool) {
    self.report = Some(report);
  }

  pub fn with_report(mut self, report: bool) -> HardeningApplyItem {
    self.report = Some(report);
    self
  }

  pub fn report(&self) -> Option<&bool> {
    self.report.as_ref()
  }

  pub fn reset_report(&mut self) {
    self.report = None;
  }

}



