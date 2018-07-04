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
pub struct JobEvent {
  /// Event flags.
  #[serde(rename = "flags")]
  flags: String,
  /// A string representation of the type of the data value.
  #[serde(rename = "fmt_type")]
  fmt_type: String,
  /// Job event ID.
  #[serde(rename = "id")]
  id: i32,
  /// Job ID.
  #[serde(rename = "job_id")]
  job_id: i32,
  /// Job Type.
  #[serde(rename = "job_type")]
  job_type: String,
  /// Event key name.
  #[serde(rename = "key")]
  key: String,
  /// Job phase number at time of event.
  #[serde(rename = "phase")]
  phase: i32,
  /// An integer representation of the type of the data value.
  #[serde(rename = "raw_type")]
  raw_type: i32,
  /// Time of event in Unix epoch seconds.
  #[serde(rename = "time")]
  time: i32,
  /// Event value.
  #[serde(rename = "value")]
  value: Option<String>
}

impl JobEvent {
  pub fn new(flags: String, fmt_type: String, id: i32, job_id: i32, job_type: String, key: String, phase: i32, raw_type: i32, time: i32) -> JobEvent {
    JobEvent {
      flags: flags,
      fmt_type: fmt_type,
      id: id,
      job_id: job_id,
      job_type: job_type,
      key: key,
      phase: phase,
      raw_type: raw_type,
      time: time,
      value: None
    }
  }

  pub fn set_flags(&mut self, flags: String) {
    self.flags = flags;
  }

  pub fn with_flags(mut self, flags: String) -> JobEvent {
    self.flags = flags;
    self
  }

  pub fn flags(&self) -> &String {
    &self.flags
  }


  pub fn set_fmt_type(&mut self, fmt_type: String) {
    self.fmt_type = fmt_type;
  }

  pub fn with_fmt_type(mut self, fmt_type: String) -> JobEvent {
    self.fmt_type = fmt_type;
    self
  }

  pub fn fmt_type(&self) -> &String {
    &self.fmt_type
  }


  pub fn set_id(&mut self, id: i32) {
    self.id = id;
  }

  pub fn with_id(mut self, id: i32) -> JobEvent {
    self.id = id;
    self
  }

  pub fn id(&self) -> &i32 {
    &self.id
  }


  pub fn set_job_id(&mut self, job_id: i32) {
    self.job_id = job_id;
  }

  pub fn with_job_id(mut self, job_id: i32) -> JobEvent {
    self.job_id = job_id;
    self
  }

  pub fn job_id(&self) -> &i32 {
    &self.job_id
  }


  pub fn set_job_type(&mut self, job_type: String) {
    self.job_type = job_type;
  }

  pub fn with_job_type(mut self, job_type: String) -> JobEvent {
    self.job_type = job_type;
    self
  }

  pub fn job_type(&self) -> &String {
    &self.job_type
  }


  pub fn set_key(&mut self, key: String) {
    self.key = key;
  }

  pub fn with_key(mut self, key: String) -> JobEvent {
    self.key = key;
    self
  }

  pub fn key(&self) -> &String {
    &self.key
  }


  pub fn set_phase(&mut self, phase: i32) {
    self.phase = phase;
  }

  pub fn with_phase(mut self, phase: i32) -> JobEvent {
    self.phase = phase;
    self
  }

  pub fn phase(&self) -> &i32 {
    &self.phase
  }


  pub fn set_raw_type(&mut self, raw_type: i32) {
    self.raw_type = raw_type;
  }

  pub fn with_raw_type(mut self, raw_type: i32) -> JobEvent {
    self.raw_type = raw_type;
    self
  }

  pub fn raw_type(&self) -> &i32 {
    &self.raw_type
  }


  pub fn set_time(&mut self, time: i32) {
    self.time = time;
  }

  pub fn with_time(mut self, time: i32) -> JobEvent {
    self.time = time;
    self
  }

  pub fn time(&self) -> &i32 {
    &self.time
  }


  pub fn set_value(&mut self, value: String) {
    self.value = Some(value);
  }

  pub fn with_value(mut self, value: String) -> JobEvent {
    self.value = Some(value);
    self
  }

  pub fn value(&self) -> Option<&String> {
    self.value.as_ref()
  }

  pub fn reset_value(&mut self) {
    self.value = None;
  }

}



