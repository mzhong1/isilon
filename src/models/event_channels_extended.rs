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
pub struct EventChannelsExtended {
  #[serde(rename = "channels")]
  channels: Option<Vec<::models::EventChannelExtendedExtended>>,
  /// Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).
  #[serde(rename = "resume")]
  resume: Option<String>,
  /// Total number of items available.
  #[serde(rename = "total")]
  total: Option<i32>
}

impl EventChannelsExtended {
  pub fn new() -> EventChannelsExtended {
    EventChannelsExtended {
      channels: None,
      resume: None,
      total: None
    }
  }

  pub fn set_channels(&mut self, channels: Vec<::models::EventChannelExtendedExtended>) {
    self.channels = Some(channels);
  }

  pub fn with_channels(mut self, channels: Vec<::models::EventChannelExtendedExtended>) -> EventChannelsExtended {
    self.channels = Some(channels);
    self
  }

  pub fn channels(&self) -> Option<&Vec<::models::EventChannelExtendedExtended>> {
    self.channels.as_ref()
  }

  pub fn reset_channels(&mut self) {
    self.channels = None;
  }

  pub fn set_resume(&mut self, resume: String) {
    self.resume = Some(resume);
  }

  pub fn with_resume(mut self, resume: String) -> EventChannelsExtended {
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

  pub fn with_total(mut self, total: i32) -> EventChannelsExtended {
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



