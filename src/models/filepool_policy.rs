/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// FilepoolPolicy : A filepool policy object

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct FilepoolPolicy {
  /// A list of actions to be taken for matching files
  #[serde(rename = "actions")]
  actions: Option<Vec<::models::FilepoolDefaultPolicyAction>>,
  /// The order in which this policy should be applied (relative to other policies)
  #[serde(rename = "apply_order")]
  apply_order: Option<i32>,
  /// A description for this policy
  #[serde(rename = "description")]
  description: Option<String>,
  /// The file matching rules for this policy
  #[serde(rename = "file_matching_pattern")]
  file_matching_pattern: Option<::models::FilepoolPolicyFileMatchingPattern>,
  /// A unique name for this policy
  #[serde(rename = "name")]
  name: Option<String>
}

impl FilepoolPolicy {
  /// A filepool policy object
  pub fn new() -> FilepoolPolicy {
    FilepoolPolicy {
      actions: None,
      apply_order: None,
      description: None,
      file_matching_pattern: None,
      name: None
    }
  }

  pub fn set_actions(&mut self, actions: Vec<::models::FilepoolDefaultPolicyAction>) {
    self.actions = Some(actions);
  }

  pub fn with_actions(mut self, actions: Vec<::models::FilepoolDefaultPolicyAction>) -> FilepoolPolicy {
    self.actions = Some(actions);
    self
  }

  pub fn actions(&self) -> Option<&Vec<::models::FilepoolDefaultPolicyAction>> {
    self.actions.as_ref()
  }

  pub fn reset_actions(&mut self) {
    self.actions = None;
  }

  pub fn set_apply_order(&mut self, apply_order: i32) {
    self.apply_order = Some(apply_order);
  }

  pub fn with_apply_order(mut self, apply_order: i32) -> FilepoolPolicy {
    self.apply_order = Some(apply_order);
    self
  }

  pub fn apply_order(&self) -> Option<&i32> {
    self.apply_order.as_ref()
  }

  pub fn reset_apply_order(&mut self) {
    self.apply_order = None;
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> FilepoolPolicy {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_file_matching_pattern(&mut self, file_matching_pattern: ::models::FilepoolPolicyFileMatchingPattern) {
    self.file_matching_pattern = Some(file_matching_pattern);
  }

  pub fn with_file_matching_pattern(mut self, file_matching_pattern: ::models::FilepoolPolicyFileMatchingPattern) -> FilepoolPolicy {
    self.file_matching_pattern = Some(file_matching_pattern);
    self
  }

  pub fn file_matching_pattern(&self) -> Option<&::models::FilepoolPolicyFileMatchingPattern> {
    self.file_matching_pattern.as_ref()
  }

  pub fn reset_file_matching_pattern(&mut self) {
    self.file_matching_pattern = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> FilepoolPolicy {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

}



