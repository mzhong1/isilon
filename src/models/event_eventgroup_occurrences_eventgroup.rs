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
pub struct EventEventgroupOccurrencesEventgroup {
  /// List of eventgroup IDs that may be causes of this occurrence.
  #[serde(rename = "causes")]
  causes: Option<Vec<Vec<String>>>,
  /// List of channels to which alerts are configured for this eventgroup
  #[serde(rename = "channels")]
  channels: Option<Vec<String>>,
  /// Number of events linked to this eventgroup.
  #[serde(rename = "event_count")]
  event_count: Option<i32>,
  /// Unique identifier of eventgroup instance.
  #[serde(rename = "eventgroup_instance")]
  eventgroup_instance: Option<String>,
  /// Same as eventgroup_instance.
  #[serde(rename = "id")]
  id: Option<String>,
  /// True if eventgroup is marked as 'ignore'.
  #[serde(rename = "ignore")]
  ignore: Option<bool>,
  /// Time eventgroup was marked as 'ignore'.
  #[serde(rename = "ignore_time")]
  ignore_time: Option<i32>,
  /// Time the most recent event was added to this eventgroup.
  #[serde(rename = "last_event")]
  last_event: Option<i32>,
  /// When the eventgroup became resolved.
  #[serde(rename = "resolve_time")]
  resolve_time: Option<i32>,
  /// True if eventgroup is resolved.
  #[serde(rename = "resolved")]
  resolved: Option<bool>,
  /// 'USER' if the eventgroup was marked resolved via PAPI <event_instance> if eventgroup was marked resolved as a result of an event.
  #[serde(rename = "resolver")]
  resolver: Option<String>,
  /// XXX description needed.
  #[serde(rename = "sequence")]
  sequence: Option<i32>,
  /// Event Group severity.
  #[serde(rename = "severity")]
  severity: Option<String>,
  /// A collection of parameters defined per eventgroup_id.
  #[serde(rename = "specifier")]
  specifier: Option<::models::Empty>,
  /// Time of first event linked to this eventgroup.
  #[serde(rename = "time_noticed")]
  time_noticed: Option<i32>
}

impl EventEventgroupOccurrencesEventgroup {
  pub fn new() -> EventEventgroupOccurrencesEventgroup {
    EventEventgroupOccurrencesEventgroup {
      causes: None,
      channels: None,
      event_count: None,
      eventgroup_instance: None,
      id: None,
      ignore: None,
      ignore_time: None,
      last_event: None,
      resolve_time: None,
      resolved: None,
      resolver: None,
      sequence: None,
      severity: None,
      specifier: None,
      time_noticed: None
    }
  }

  pub fn set_causes(&mut self, causes: Vec<Vec<String>>) {
    self.causes = Some(causes);
  }

  pub fn with_causes(mut self, causes: Vec<Vec<String>>) -> EventEventgroupOccurrencesEventgroup {
    self.causes = Some(causes);
    self
  }

  pub fn causes(&self) -> Option<&Vec<Vec<String>>> {
    self.causes.as_ref()
  }

  pub fn reset_causes(&mut self) {
    self.causes = None;
  }

  pub fn set_channels(&mut self, channels: Vec<String>) {
    self.channels = Some(channels);
  }

  pub fn with_channels(mut self, channels: Vec<String>) -> EventEventgroupOccurrencesEventgroup {
    self.channels = Some(channels);
    self
  }

  pub fn channels(&self) -> Option<&Vec<String>> {
    self.channels.as_ref()
  }

  pub fn reset_channels(&mut self) {
    self.channels = None;
  }

  pub fn set_event_count(&mut self, event_count: i32) {
    self.event_count = Some(event_count);
  }

  pub fn with_event_count(mut self, event_count: i32) -> EventEventgroupOccurrencesEventgroup {
    self.event_count = Some(event_count);
    self
  }

  pub fn event_count(&self) -> Option<&i32> {
    self.event_count.as_ref()
  }

  pub fn reset_event_count(&mut self) {
    self.event_count = None;
  }

  pub fn set_eventgroup_instance(&mut self, eventgroup_instance: String) {
    self.eventgroup_instance = Some(eventgroup_instance);
  }

  pub fn with_eventgroup_instance(mut self, eventgroup_instance: String) -> EventEventgroupOccurrencesEventgroup {
    self.eventgroup_instance = Some(eventgroup_instance);
    self
  }

  pub fn eventgroup_instance(&self) -> Option<&String> {
    self.eventgroup_instance.as_ref()
  }

  pub fn reset_eventgroup_instance(&mut self) {
    self.eventgroup_instance = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> EventEventgroupOccurrencesEventgroup {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_ignore(&mut self, ignore: bool) {
    self.ignore = Some(ignore);
  }

  pub fn with_ignore(mut self, ignore: bool) -> EventEventgroupOccurrencesEventgroup {
    self.ignore = Some(ignore);
    self
  }

  pub fn ignore(&self) -> Option<&bool> {
    self.ignore.as_ref()
  }

  pub fn reset_ignore(&mut self) {
    self.ignore = None;
  }

  pub fn set_ignore_time(&mut self, ignore_time: i32) {
    self.ignore_time = Some(ignore_time);
  }

  pub fn with_ignore_time(mut self, ignore_time: i32) -> EventEventgroupOccurrencesEventgroup {
    self.ignore_time = Some(ignore_time);
    self
  }

  pub fn ignore_time(&self) -> Option<&i32> {
    self.ignore_time.as_ref()
  }

  pub fn reset_ignore_time(&mut self) {
    self.ignore_time = None;
  }

  pub fn set_last_event(&mut self, last_event: i32) {
    self.last_event = Some(last_event);
  }

  pub fn with_last_event(mut self, last_event: i32) -> EventEventgroupOccurrencesEventgroup {
    self.last_event = Some(last_event);
    self
  }

  pub fn last_event(&self) -> Option<&i32> {
    self.last_event.as_ref()
  }

  pub fn reset_last_event(&mut self) {
    self.last_event = None;
  }

  pub fn set_resolve_time(&mut self, resolve_time: i32) {
    self.resolve_time = Some(resolve_time);
  }

  pub fn with_resolve_time(mut self, resolve_time: i32) -> EventEventgroupOccurrencesEventgroup {
    self.resolve_time = Some(resolve_time);
    self
  }

  pub fn resolve_time(&self) -> Option<&i32> {
    self.resolve_time.as_ref()
  }

  pub fn reset_resolve_time(&mut self) {
    self.resolve_time = None;
  }

  pub fn set_resolved(&mut self, resolved: bool) {
    self.resolved = Some(resolved);
  }

  pub fn with_resolved(mut self, resolved: bool) -> EventEventgroupOccurrencesEventgroup {
    self.resolved = Some(resolved);
    self
  }

  pub fn resolved(&self) -> Option<&bool> {
    self.resolved.as_ref()
  }

  pub fn reset_resolved(&mut self) {
    self.resolved = None;
  }

  pub fn set_resolver(&mut self, resolver: String) {
    self.resolver = Some(resolver);
  }

  pub fn with_resolver(mut self, resolver: String) -> EventEventgroupOccurrencesEventgroup {
    self.resolver = Some(resolver);
    self
  }

  pub fn resolver(&self) -> Option<&String> {
    self.resolver.as_ref()
  }

  pub fn reset_resolver(&mut self) {
    self.resolver = None;
  }

  pub fn set_sequence(&mut self, sequence: i32) {
    self.sequence = Some(sequence);
  }

  pub fn with_sequence(mut self, sequence: i32) -> EventEventgroupOccurrencesEventgroup {
    self.sequence = Some(sequence);
    self
  }

  pub fn sequence(&self) -> Option<&i32> {
    self.sequence.as_ref()
  }

  pub fn reset_sequence(&mut self) {
    self.sequence = None;
  }

  pub fn set_severity(&mut self, severity: String) {
    self.severity = Some(severity);
  }

  pub fn with_severity(mut self, severity: String) -> EventEventgroupOccurrencesEventgroup {
    self.severity = Some(severity);
    self
  }

  pub fn severity(&self) -> Option<&String> {
    self.severity.as_ref()
  }

  pub fn reset_severity(&mut self) {
    self.severity = None;
  }

  pub fn set_specifier(&mut self, specifier: ::models::Empty) {
    self.specifier = Some(specifier);
  }

  pub fn with_specifier(mut self, specifier: ::models::Empty) -> EventEventgroupOccurrencesEventgroup {
    self.specifier = Some(specifier);
    self
  }

  pub fn specifier(&self) -> Option<&::models::Empty> {
    self.specifier.as_ref()
  }

  pub fn reset_specifier(&mut self) {
    self.specifier = None;
  }

  pub fn set_time_noticed(&mut self, time_noticed: i32) {
    self.time_noticed = Some(time_noticed);
  }

  pub fn with_time_noticed(mut self, time_noticed: i32) -> EventEventgroupOccurrencesEventgroup {
    self.time_noticed = Some(time_noticed);
    self
  }

  pub fn time_noticed(&self) -> Option<&i32> {
    self.time_noticed.as_ref()
  }

  pub fn reset_time_noticed(&mut self) {
    self.time_noticed = None;
  }

}



