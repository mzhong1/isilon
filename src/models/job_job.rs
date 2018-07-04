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
pub struct JobJob {
  /// Impact policy of this job instance.
  #[serde(rename = "policy")]
  policy: Option<String>,
  /// Priority of this job instance; lower numbers preempt higher numbers.
  #[serde(rename = "priority")]
  priority: Option<i32>,
  /// Desired new state of this job instance.
  #[serde(rename = "state")]
  state: Option<String>
}

impl JobJob {
  pub fn new() -> JobJob {
    JobJob {
      policy: None,
      priority: None,
      state: None
    }
  }

  pub fn set_policy(&mut self, policy: String) {
    self.policy = Some(policy);
  }

  pub fn with_policy(mut self, policy: String) -> JobJob {
    self.policy = Some(policy);
    self
  }

  pub fn policy(&self) -> Option<&String> {
    self.policy.as_ref()
  }

  pub fn reset_policy(&mut self) {
    self.policy = None;
  }

  pub fn set_priority(&mut self, priority: i32) {
    self.priority = Some(priority);
  }

  pub fn with_priority(mut self, priority: i32) -> JobJob {
    self.priority = Some(priority);
    self
  }

  pub fn priority(&self) -> Option<&i32> {
    self.priority.as_ref()
  }

  pub fn reset_priority(&mut self) {
    self.priority = None;
  }

  pub fn set_state(&mut self, state: String) {
    self.state = Some(state);
  }

  pub fn with_state(mut self, state: String) -> JobJob {
    self.state = Some(state);
    self
  }

  pub fn state(&self) -> Option<&String> {
    self.state.as_ref()
  }

  pub fn reset_state(&mut self) {
    self.state = None;
  }

}



