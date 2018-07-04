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
pub struct StatisticsCurrentStat {
  /// Devid of node of statistic or 0 for cluster scoped statistics.
  #[serde(rename = "devid")]
  devid: i32,
  /// Key specific error string, if applicable.
  #[serde(rename = "error")]
  error: Option<String>,
  /// Key specific error number, if applicable.
  #[serde(rename = "error_code")]
  error_code: Option<i32>,
  /// Key name of statistic.
  #[serde(rename = "key")]
  key: String,
  /// Unix Epoch time in seconds that statistic was collected.
  #[serde(rename = "time")]
  time: i32,
  /// Key dependent value.
  #[serde(rename = "value")]
  value: Option<String>
}

impl StatisticsCurrentStat {
  pub fn new(devid: i32, key: String, time: i32) -> StatisticsCurrentStat {
    StatisticsCurrentStat {
      devid: devid,
      error: None,
      error_code: None,
      key: key,
      time: time,
      value: None
    }
  }

  pub fn set_devid(&mut self, devid: i32) {
    self.devid = devid;
  }

  pub fn with_devid(mut self, devid: i32) -> StatisticsCurrentStat {
    self.devid = devid;
    self
  }

  pub fn devid(&self) -> &i32 {
    &self.devid
  }


  pub fn set_error(&mut self, error: String) {
    self.error = Some(error);
  }

  pub fn with_error(mut self, error: String) -> StatisticsCurrentStat {
    self.error = Some(error);
    self
  }

  pub fn error(&self) -> Option<&String> {
    self.error.as_ref()
  }

  pub fn reset_error(&mut self) {
    self.error = None;
  }

  pub fn set_error_code(&mut self, error_code: i32) {
    self.error_code = Some(error_code);
  }

  pub fn with_error_code(mut self, error_code: i32) -> StatisticsCurrentStat {
    self.error_code = Some(error_code);
    self
  }

  pub fn error_code(&self) -> Option<&i32> {
    self.error_code.as_ref()
  }

  pub fn reset_error_code(&mut self) {
    self.error_code = None;
  }

  pub fn set_key(&mut self, key: String) {
    self.key = key;
  }

  pub fn with_key(mut self, key: String) -> StatisticsCurrentStat {
    self.key = key;
    self
  }

  pub fn key(&self) -> &String {
    &self.key
  }


  pub fn set_time(&mut self, time: i32) {
    self.time = time;
  }

  pub fn with_time(mut self, time: i32) -> StatisticsCurrentStat {
    self.time = time;
    self
  }

  pub fn time(&self) -> &i32 {
    &self.time
  }


  pub fn set_value(&mut self, value: String) {
    self.value = Some(value);
  }

  pub fn with_value(mut self, value: String) -> StatisticsCurrentStat {
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



