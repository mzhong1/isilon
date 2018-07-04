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
pub struct SyncRuleExtended {
  /// User-entered description of this performance rule.
  #[serde(rename = "description")]
  description: String,
  /// Whether this performance rule is currently in effect during its specified intervals.
  #[serde(rename = "enabled")]
  enabled: bool,
  /// Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, processing percentage used for cpu, or percentage of maximum available workers.
  #[serde(rename = "limit")]
  limit: i32,
  /// A schedule defining when during a week this performance rule is in effect.  If unspecified or null, the schedule will always be in effect.
  #[serde(rename = "schedule")]
  schedule: Option<::models::SyncRuleSchedule>,
  /// The system ID given to this performance rule.
  #[serde(rename = "id")]
  id: String,
  /// The type of system resource this rule limits.
  #[serde(rename = "type")]
  _type: String
}

impl SyncRuleExtended {
  pub fn new(description: String, enabled: bool, limit: i32, id: String, _type: String) -> SyncRuleExtended {
    SyncRuleExtended {
      description: description,
      enabled: enabled,
      limit: limit,
      schedule: None,
      id: id,
      _type: _type
    }
  }

  pub fn set_description(&mut self, description: String) {
    self.description = description;
  }

  pub fn with_description(mut self, description: String) -> SyncRuleExtended {
    self.description = description;
    self
  }

  pub fn description(&self) -> &String {
    &self.description
  }


  pub fn set_enabled(&mut self, enabled: bool) {
    self.enabled = enabled;
  }

  pub fn with_enabled(mut self, enabled: bool) -> SyncRuleExtended {
    self.enabled = enabled;
    self
  }

  pub fn enabled(&self) -> &bool {
    &self.enabled
  }


  pub fn set_limit(&mut self, limit: i32) {
    self.limit = limit;
  }

  pub fn with_limit(mut self, limit: i32) -> SyncRuleExtended {
    self.limit = limit;
    self
  }

  pub fn limit(&self) -> &i32 {
    &self.limit
  }


  pub fn set_schedule(&mut self, schedule: ::models::SyncRuleSchedule) {
    self.schedule = Some(schedule);
  }

  pub fn with_schedule(mut self, schedule: ::models::SyncRuleSchedule) -> SyncRuleExtended {
    self.schedule = Some(schedule);
    self
  }

  pub fn schedule(&self) -> Option<&::models::SyncRuleSchedule> {
    self.schedule.as_ref()
  }

  pub fn reset_schedule(&mut self) {
    self.schedule = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> SyncRuleExtended {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


  pub fn set__type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with__type(mut self, _type: String) -> SyncRuleExtended {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


}



