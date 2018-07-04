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
pub struct SnapshotAlias {
  /// The user or system supplied snapshot alias name.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Target snapshot for this snapshot alias.
  #[serde(rename = "target")]
  target: Option<String>
}

impl SnapshotAlias {
  pub fn new() -> SnapshotAlias {
    SnapshotAlias {
      name: None,
      target: None
    }
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> SnapshotAlias {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_target(&mut self, target: String) {
    self.target = Some(target);
  }

  pub fn with_target(mut self, target: String) -> SnapshotAlias {
    self.target = Some(target);
    self
  }

  pub fn target(&self) -> Option<&String> {
    self.target.as_ref()
  }

  pub fn reset_target(&mut self) {
    self.target = None;
  }

}



