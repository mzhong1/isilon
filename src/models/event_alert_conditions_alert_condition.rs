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
pub struct EventAlertConditionsAlertCondition {
  /// Event Group categories to be alerted: all, 100000000 (SYS_DISK_EVENTS), 200000000 (NODE_STATUS_EVENTS), 300000000 (REBOOT_EVENTS), 400000000 (SW_EVENTS), 500000000 (QUOTA_EVENTS), 600000000 (SNAP_EVENTS), 700000000 (WINNET_EVENTS), 800000000 (FILESYS_EVENTS), 900000000 (HW_EVENTS), 1100000000 (CPOOL_EVENTS)
  #[serde(rename = "categories")]
  categories: Option<Vec<String>>,
  /// Channels for alert
  #[serde(rename = "channels")]
  channels: Option<Vec<String>>,
  /// Trigger condition for alert
  #[serde(rename = "condition")]
  condition: Option<String>,
  /// Event Group IDs to be alerted
  #[serde(rename = "eventgroup_ids")]
  eventgroup_ids: Option<Vec<String>>,
  /// Unique identifier.
  #[serde(rename = "id")]
  id: Option<String>,
  /// Required with ONGOING condition only, period in seconds between alerts of ongoing conditions
  #[serde(rename = "interval")]
  interval: Option<i32>,
  /// Required with NEW EVENTS condition only, limits the number of alerts sent as events are added
  #[serde(rename = "limit")]
  limit: Option<i32>,
  /// Unique identifier.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Severities to be alerted
  #[serde(rename = "severities")]
  severities: Option<Vec<String>>,
  /// Any eventgroup lasting less than this many seconds is deemed transient and will not generate alerts under this condition.
  #[serde(rename = "transient")]
  transient: Option<i32>
}

impl EventAlertConditionsAlertCondition {
  pub fn new() -> EventAlertConditionsAlertCondition {
    EventAlertConditionsAlertCondition {
      categories: None,
      channels: None,
      condition: None,
      eventgroup_ids: None,
      id: None,
      interval: None,
      limit: None,
      name: None,
      severities: None,
      transient: None
    }
  }

  pub fn set_categories(&mut self, categories: Vec<String>) {
    self.categories = Some(categories);
  }

  pub fn with_categories(mut self, categories: Vec<String>) -> EventAlertConditionsAlertCondition {
    self.categories = Some(categories);
    self
  }

  pub fn categories(&self) -> Option<&Vec<String>> {
    self.categories.as_ref()
  }

  pub fn reset_categories(&mut self) {
    self.categories = None;
  }

  pub fn set_channels(&mut self, channels: Vec<String>) {
    self.channels = Some(channels);
  }

  pub fn with_channels(mut self, channels: Vec<String>) -> EventAlertConditionsAlertCondition {
    self.channels = Some(channels);
    self
  }

  pub fn channels(&self) -> Option<&Vec<String>> {
    self.channels.as_ref()
  }

  pub fn reset_channels(&mut self) {
    self.channels = None;
  }

  pub fn set_condition(&mut self, condition: String) {
    self.condition = Some(condition);
  }

  pub fn with_condition(mut self, condition: String) -> EventAlertConditionsAlertCondition {
    self.condition = Some(condition);
    self
  }

  pub fn condition(&self) -> Option<&String> {
    self.condition.as_ref()
  }

  pub fn reset_condition(&mut self) {
    self.condition = None;
  }

  pub fn set_eventgroup_ids(&mut self, eventgroup_ids: Vec<String>) {
    self.eventgroup_ids = Some(eventgroup_ids);
  }

  pub fn with_eventgroup_ids(mut self, eventgroup_ids: Vec<String>) -> EventAlertConditionsAlertCondition {
    self.eventgroup_ids = Some(eventgroup_ids);
    self
  }

  pub fn eventgroup_ids(&self) -> Option<&Vec<String>> {
    self.eventgroup_ids.as_ref()
  }

  pub fn reset_eventgroup_ids(&mut self) {
    self.eventgroup_ids = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> EventAlertConditionsAlertCondition {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_interval(&mut self, interval: i32) {
    self.interval = Some(interval);
  }

  pub fn with_interval(mut self, interval: i32) -> EventAlertConditionsAlertCondition {
    self.interval = Some(interval);
    self
  }

  pub fn interval(&self) -> Option<&i32> {
    self.interval.as_ref()
  }

  pub fn reset_interval(&mut self) {
    self.interval = None;
  }

  pub fn set_limit(&mut self, limit: i32) {
    self.limit = Some(limit);
  }

  pub fn with_limit(mut self, limit: i32) -> EventAlertConditionsAlertCondition {
    self.limit = Some(limit);
    self
  }

  pub fn limit(&self) -> Option<&i32> {
    self.limit.as_ref()
  }

  pub fn reset_limit(&mut self) {
    self.limit = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> EventAlertConditionsAlertCondition {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_severities(&mut self, severities: Vec<String>) {
    self.severities = Some(severities);
  }

  pub fn with_severities(mut self, severities: Vec<String>) -> EventAlertConditionsAlertCondition {
    self.severities = Some(severities);
    self
  }

  pub fn severities(&self) -> Option<&Vec<String>> {
    self.severities.as_ref()
  }

  pub fn reset_severities(&mut self) {
    self.severities = None;
  }

  pub fn set_transient(&mut self, transient: i32) {
    self.transient = Some(transient);
  }

  pub fn with_transient(mut self, transient: i32) -> EventAlertConditionsAlertCondition {
    self.transient = Some(transient);
    self
  }

  pub fn transient(&self) -> Option<&i32> {
    self.transient.as_ref()
  }

  pub fn reset_transient(&mut self) {
    self.transient = None;
  }

}



