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
pub struct StoragepoolSettingsSettingsSpilloverTarget {
  /// Target pool ID if target specified, otherwise null.
  #[serde(rename = "id")]
  id: Option<i32>,
  /// Target pool name if target specified, otherwise null.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Type of target pool.
  #[serde(rename = "type")]
  _type: String
}

impl StoragepoolSettingsSettingsSpilloverTarget {
  pub fn new(_type: String) -> StoragepoolSettingsSettingsSpilloverTarget {
    StoragepoolSettingsSettingsSpilloverTarget {
      id: None,
      name: None,
      _type: _type
    }
  }

  pub fn set_id(&mut self, id: i32) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: i32) -> StoragepoolSettingsSettingsSpilloverTarget {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&i32> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> StoragepoolSettingsSettingsSpilloverTarget {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with_type(mut self, _type: String) -> StoragepoolSettingsSettingsSpilloverTarget {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


}



