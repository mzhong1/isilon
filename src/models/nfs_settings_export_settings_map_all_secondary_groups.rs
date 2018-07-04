/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// NfsSettingsExportSettingsMapAllSecondaryGroups : Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct NfsSettingsExportSettingsMapAllSecondaryGroups {
  /// Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.
  #[serde(rename = "id")]
  id: Option<String>,
  /// Specifies the persona name, which must be combined with a type.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Specifies the type of persona, which must be combined with a name.
  #[serde(rename = "type")]
  _type: Option<String>
}

impl NfsSettingsExportSettingsMapAllSecondaryGroups {
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  pub fn new() -> NfsSettingsExportSettingsMapAllSecondaryGroups {
    NfsSettingsExportSettingsMapAllSecondaryGroups {
      id: None,
      name: None,
      _type: None
    }
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> NfsSettingsExportSettingsMapAllSecondaryGroups {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> NfsSettingsExportSettingsMapAllSecondaryGroups {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set__type(&mut self, _type: String) {
    self._type = Some(_type);
  }

  pub fn with__type(mut self, _type: String) -> NfsSettingsExportSettingsMapAllSecondaryGroups {
    self._type = Some(_type);
    self
  }

  pub fn _type(&self) -> Option<&String> {
    self._type.as_ref()
  }

  pub fn reset__type(&mut self) {
    self._type = None;
  }

}



