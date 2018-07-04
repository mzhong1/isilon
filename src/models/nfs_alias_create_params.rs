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
pub struct NfsAliasCreateParams {
  /// Specifies whether the alias is usable.
  #[serde(rename = "health")]
  health: Option<String>,
  /// Specifies the name by which the alias can be referenced.
  #[serde(rename = "name")]
  name: String,
  /// Specifies the path to which the alias points.
  #[serde(rename = "path")]
  path: String,
  /// Specifies the zone in which the alias is valid.
  #[serde(rename = "zone")]
  zone: Option<String>
}

impl NfsAliasCreateParams {
  pub fn new(name: String, path: String) -> NfsAliasCreateParams {
    NfsAliasCreateParams {
      health: None,
      name: name,
      path: path,
      zone: None
    }
  }

  pub fn set_health(&mut self, health: String) {
    self.health = Some(health);
  }

  pub fn with_health(mut self, health: String) -> NfsAliasCreateParams {
    self.health = Some(health);
    self
  }

  pub fn health(&self) -> Option<&String> {
    self.health.as_ref()
  }

  pub fn reset_health(&mut self) {
    self.health = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = name;
  }

  pub fn with_name(mut self, name: String) -> NfsAliasCreateParams {
    self.name = name;
    self
  }

  pub fn name(&self) -> &String {
    &self.name
  }


  pub fn set_path(&mut self, path: String) {
    self.path = path;
  }

  pub fn with_path(mut self, path: String) -> NfsAliasCreateParams {
    self.path = path;
    self
  }

  pub fn path(&self) -> &String {
    &self.path
  }


  pub fn set_zone(&mut self, zone: String) {
    self.zone = Some(zone);
  }

  pub fn with_zone(mut self, zone: String) -> NfsAliasCreateParams {
    self.zone = Some(zone);
    self
  }

  pub fn zone(&self) -> Option<&String> {
    self.zone.as_ref()
  }

  pub fn reset_zone(&mut self) {
    self.zone = None;
  }

}



