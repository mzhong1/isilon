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
pub struct SyncJobPolicyFileMatchingPatternOrCriteriaItem {
  /// An array containing individual file criterion objects each describing one criterion.  These are logically AND'ed together to form a set of criteria.
  #[serde(rename = "and_criteria")]
  and_criteria: Option<Vec<::models::SyncJobPolicyFileMatchingPatternOrCriteriaItemAndCriteriaItem>>
}

impl SyncJobPolicyFileMatchingPatternOrCriteriaItem {
  pub fn new() -> SyncJobPolicyFileMatchingPatternOrCriteriaItem {
    SyncJobPolicyFileMatchingPatternOrCriteriaItem {
      and_criteria: None
    }
  }

  pub fn set_and_criteria(&mut self, and_criteria: Vec<::models::SyncJobPolicyFileMatchingPatternOrCriteriaItemAndCriteriaItem>) {
    self.and_criteria = Some(and_criteria);
  }

  pub fn with_and_criteria(mut self, and_criteria: Vec<::models::SyncJobPolicyFileMatchingPatternOrCriteriaItemAndCriteriaItem>) -> SyncJobPolicyFileMatchingPatternOrCriteriaItem {
    self.and_criteria = Some(and_criteria);
    self
  }

  pub fn and_criteria(&self) -> Option<&Vec<::models::SyncJobPolicyFileMatchingPatternOrCriteriaItemAndCriteriaItem>> {
    self.and_criteria.as_ref()
  }

  pub fn reset_and_criteria(&mut self) {
    self.and_criteria = None;
  }

}



