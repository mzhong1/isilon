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
pub struct NodeStatusNodeCapacityItem {
  /// Total device storage bytes.
  #[serde(rename = "bytes")]
  bytes: Option<i32>,
  /// Total device count.
  #[serde(rename = "count")]
  count: Option<i32>,
  /// Device type.
  #[serde(rename = "type")]
  _type: Option<String>
}

impl NodeStatusNodeCapacityItem {
  pub fn new() -> NodeStatusNodeCapacityItem {
    NodeStatusNodeCapacityItem {
      bytes: None,
      count: None,
      _type: None
    }
  }

  pub fn set_bytes(&mut self, bytes: i32) {
    self.bytes = Some(bytes);
  }

  pub fn with_bytes(mut self, bytes: i32) -> NodeStatusNodeCapacityItem {
    self.bytes = Some(bytes);
    self
  }

  pub fn bytes(&self) -> Option<&i32> {
    self.bytes.as_ref()
  }

  pub fn reset_bytes(&mut self) {
    self.bytes = None;
  }

  pub fn set_count(&mut self, count: i32) {
    self.count = Some(count);
  }

  pub fn with_count(mut self, count: i32) -> NodeStatusNodeCapacityItem {
    self.count = Some(count);
    self
  }

  pub fn count(&self) -> Option<&i32> {
    self.count.as_ref()
  }

  pub fn reset_count(&mut self) {
    self.count = None;
  }

  pub fn set_type(&mut self, _type: String) {
    self._type = Some(_type);
  }

  pub fn with_type(mut self, _type: String) -> NodeStatusNodeCapacityItem {
    self._type = Some(_type);
    self
  }

  pub fn _type(&self) -> Option<&String> {
    self._type.as_ref()
  }

  pub fn reset_type(&mut self) {
    self._type = None;
  }

}



