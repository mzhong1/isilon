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
pub struct EventEventgroupDefinitionsEventgroupDefinition {
  /// ID of eventgroup category: all, 100000000 (SYS_DISK_EVENTS), 200000000 (NODE_STATUS_EVENTS), 300000000 (REBOOT_EVENTS), 400000000 (SW_EVENTS), 500000000 (QUOTA_EVENTS), 600000000 (SNAP_EVENTS), 700000000 (WINNET_EVENTS), 800000000 (FILESYS_EVENTS), 900000000 (HW_EVENTS), 1100000000 (CPOOL_EVENTS)
  #[serde(rename = "category")]
  category: Option<String>,
  /// Human readable description - may contain value placeholders.
  #[serde(rename = "description")]
  description: Option<String>,
  /// Unique Identifier.
  #[serde(rename = "id")]
  id: Option<String>,
  /// Name for eventgroup.
  #[serde(rename = "name")]
  name: Option<String>
}

impl EventEventgroupDefinitionsEventgroupDefinition {
  pub fn new() -> EventEventgroupDefinitionsEventgroupDefinition {
    EventEventgroupDefinitionsEventgroupDefinition {
      category: None,
      description: None,
      id: None,
      name: None
    }
  }

  pub fn set_category(&mut self, category: String) {
    self.category = Some(category);
  }

  pub fn with_category(mut self, category: String) -> EventEventgroupDefinitionsEventgroupDefinition {
    self.category = Some(category);
    self
  }

  pub fn category(&self) -> Option<&String> {
    self.category.as_ref()
  }

  pub fn reset_category(&mut self) {
    self.category = None;
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> EventEventgroupDefinitionsEventgroupDefinition {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> EventEventgroupDefinitionsEventgroupDefinition {
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

  pub fn with_name(mut self, name: String) -> EventEventgroupDefinitionsEventgroupDefinition {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

}



