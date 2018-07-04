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
pub struct FilepoolPolicies {
  #[serde(rename = "policies")]
  policies: Option<Vec<::models::FilepoolPolicyExtended>>,
  /// Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).
  #[serde(rename = "resume")]
  resume: Option<String>,
  /// Total number of items available.
  #[serde(rename = "total")]
  total: Option<i32>
}

impl FilepoolPolicies {
  pub fn new() -> FilepoolPolicies {
    FilepoolPolicies {
      policies: None,
      resume: None,
      total: None
    }
  }

  pub fn set_policies(&mut self, policies: Vec<::models::FilepoolPolicyExtended>) {
    self.policies = Some(policies);
  }

  pub fn with_policies(mut self, policies: Vec<::models::FilepoolPolicyExtended>) -> FilepoolPolicies {
    self.policies = Some(policies);
    self
  }

  pub fn policies(&self) -> Option<&Vec<::models::FilepoolPolicyExtended>> {
    self.policies.as_ref()
  }

  pub fn reset_policies(&mut self) {
    self.policies = None;
  }

  pub fn set_resume(&mut self, resume: String) {
    self.resume = Some(resume);
  }

  pub fn with_resume(mut self, resume: String) -> FilepoolPolicies {
    self.resume = Some(resume);
    self
  }

  pub fn resume(&self) -> Option<&String> {
    self.resume.as_ref()
  }

  pub fn reset_resume(&mut self) {
    self.resume = None;
  }

  pub fn set_total(&mut self, total: i32) {
    self.total = Some(total);
  }

  pub fn with_total(mut self, total: i32) -> FilepoolPolicies {
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



