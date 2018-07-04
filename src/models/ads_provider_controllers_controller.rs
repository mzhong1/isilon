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
pub struct AdsProviderControllersController {
  /// Specifies the address for the domain controller.
  #[serde(rename = "dc_address")]
  dc_address: Option<String>,
  /// Specifies the name of the domain controller.
  #[serde(rename = "dc_name")]
  dc_name: Option<String>,
  /// Specifies the address for the domain controller. This value is the same as the 'dc_address' value.
  #[serde(rename = "id")]
  id: Option<String>
}

impl AdsProviderControllersController {
  pub fn new() -> AdsProviderControllersController {
    AdsProviderControllersController {
      dc_address: None,
      dc_name: None,
      id: None
    }
  }

  pub fn set_dc_address(&mut self, dc_address: String) {
    self.dc_address = Some(dc_address);
  }

  pub fn with_dc_address(mut self, dc_address: String) -> AdsProviderControllersController {
    self.dc_address = Some(dc_address);
    self
  }

  pub fn dc_address(&self) -> Option<&String> {
    self.dc_address.as_ref()
  }

  pub fn reset_dc_address(&mut self) {
    self.dc_address = None;
  }

  pub fn set_dc_name(&mut self, dc_name: String) {
    self.dc_name = Some(dc_name);
  }

  pub fn with_dc_name(mut self, dc_name: String) -> AdsProviderControllersController {
    self.dc_name = Some(dc_name);
    self
  }

  pub fn dc_name(&self) -> Option<&String> {
    self.dc_name.as_ref()
  }

  pub fn reset_dc_name(&mut self) {
    self.dc_name = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> AdsProviderControllersController {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

}



