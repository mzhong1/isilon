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
pub struct AntivirusServerExtended {
  /// A description for the server.
  #[serde(rename = "description")]
  description: Option<String>,
  /// Whether the server is enabled.
  #[serde(rename = "enabled")]
  enabled: Option<bool>,
  /// The icap url for the server.  This should have a format of: icap://host.domain:port/path
  #[serde(rename = "url")]
  url: Option<String>,
  #[serde(rename = "definitions")]
  definitions: Option<String>,
  /// A unique identifier for the server.
  #[serde(rename = "id")]
  id: Option<String>,
  /// The status of the server.
  #[serde(rename = "status")]
  status: Option<String>
}

impl AntivirusServerExtended {
  pub fn new() -> AntivirusServerExtended {
    AntivirusServerExtended {
      description: None,
      enabled: None,
      url: None,
      definitions: None,
      id: None,
      status: None
    }
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> AntivirusServerExtended {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_enabled(&mut self, enabled: bool) {
    self.enabled = Some(enabled);
  }

  pub fn with_enabled(mut self, enabled: bool) -> AntivirusServerExtended {
    self.enabled = Some(enabled);
    self
  }

  pub fn enabled(&self) -> Option<&bool> {
    self.enabled.as_ref()
  }

  pub fn reset_enabled(&mut self) {
    self.enabled = None;
  }

  pub fn set_url(&mut self, url: String) {
    self.url = Some(url);
  }

  pub fn with_url(mut self, url: String) -> AntivirusServerExtended {
    self.url = Some(url);
    self
  }

  pub fn url(&self) -> Option<&String> {
    self.url.as_ref()
  }

  pub fn reset_url(&mut self) {
    self.url = None;
  }

  pub fn set_definitions(&mut self, definitions: String) {
    self.definitions = Some(definitions);
  }

  pub fn with_definitions(mut self, definitions: String) -> AntivirusServerExtended {
    self.definitions = Some(definitions);
    self
  }

  pub fn definitions(&self) -> Option<&String> {
    self.definitions.as_ref()
  }

  pub fn reset_definitions(&mut self) {
    self.definitions = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> AntivirusServerExtended {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_status(&mut self, status: String) {
    self.status = Some(status);
  }

  pub fn with_status(mut self, status: String) -> AntivirusServerExtended {
    self.status = Some(status);
    self
  }

  pub fn status(&self) -> Option<&String> {
    self.status.as_ref()
  }

  pub fn reset_status(&mut self) {
    self.status = None;
  }

}



