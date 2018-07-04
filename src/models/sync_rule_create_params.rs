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
pub struct SyncRuleCreateParams {
  /// User-entered description of this performance rule.
  #[serde(rename = "description")]
  description: Option<String>,
  /// Whether this performance rule is currently in effect during its specified intervals.
  #[serde(rename = "enabled")]
  enabled: Option<bool>,
  /// Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, processing percentage used for cpu, or percentage of maximum available workers.
  #[serde(rename = "limit")]
  limit: i32,
  /// A schedule defining when during a week this performance rule is in effect.  If unspecified or null, the schedule will always be in effect.
  #[serde(rename = "schedule")]
  schedule: Option<::models::SyncRuleSchedule>,
  /// The type of system resource this rule limits.
  #[serde(rename = "type")]
  _type: String
}

impl SyncRuleCreateParams {
  pub fn new(limit: i32, _type: String) -> SyncRuleCreateParams {
    SyncRuleCreateParams {
      description: None,
      enabled: None,
      limit: limit,
      schedule: None,
      _type: _type
    }
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> SyncRuleCreateParams {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_enabled(&mut self, enabled: bool) {
    self.enabled = Some(enabled);
  }

  pub fn with_enabled(mut self, enabled: bool) -> SyncRuleCreateParams {
    self.enabled = Some(enabled);
    self
  }

  pub fn enabled(&self) -> Option<&bool> {
    self.enabled.as_ref()
  }

  pub fn reset_enabled(&mut self) {
    self.enabled = None;
  }

  pub fn set_limit(&mut self, limit: i32) {
    self.limit = limit;
  }

  pub fn with_limit(mut self, limit: i32) -> SyncRuleCreateParams {
    self.limit = limit;
    self
  }

  pub fn limit(&self) -> &i32 {
    &self.limit
  }


  pub fn set_schedule(&mut self, schedule: ::models::SyncRuleSchedule) {
    self.schedule = Some(schedule);
  }

  pub fn with_schedule(mut self, schedule: ::models::SyncRuleSchedule) -> SyncRuleCreateParams {
    self.schedule = Some(schedule);
    self
  }

  pub fn schedule(&self) -> Option<&::models::SyncRuleSchedule> {
    self.schedule.as_ref()
  }

  pub fn reset_schedule(&mut self) {
    self.schedule = None;
  }

  pub fn set__type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with__type(mut self, _type: String) -> SyncRuleCreateParams {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


}



