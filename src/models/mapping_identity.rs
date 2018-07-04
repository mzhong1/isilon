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
pub struct MappingIdentity {
  /// Specifies the identity mapping entry id.
  #[serde(rename = "id")]
  id: String,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "source")]
  source: Option<::models::AuthAccessAccessItemFileGroup>,
  #[serde(rename = "targets")]
  targets: Vec<::models::MappingIdentityTarget>
}

impl MappingIdentity {
  pub fn new(id: String, targets: Vec<::models::MappingIdentityTarget>) -> MappingIdentity {
    MappingIdentity {
      id: id,
      source: None,
      targets: targets
    }
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> MappingIdentity {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


  pub fn set_source(&mut self, source: ::models::AuthAccessAccessItemFileGroup) {
    self.source = Some(source);
  }

  pub fn with_source(mut self, source: ::models::AuthAccessAccessItemFileGroup) -> MappingIdentity {
    self.source = Some(source);
    self
  }

  pub fn source(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.source.as_ref()
  }

  pub fn reset_source(&mut self) {
    self.source = None;
  }

  pub fn set_targets(&mut self, targets: Vec<::models::MappingIdentityTarget>) {
    self.targets = targets;
  }

  pub fn with_targets(mut self, targets: Vec<::models::MappingIdentityTarget>) -> MappingIdentity {
    self.targets = targets;
    self
  }

  pub fn targets(&self) -> &Vec<::models::MappingIdentityTarget> {
    &self.targets
  }


}



