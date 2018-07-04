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
pub struct ClusterNodesAvailableNode {
  /// Node configuration ID.
  #[serde(rename = "configuration_id")]
  configuration_id: Option<String>,
  /// Human-readable description giving further detail on status (may be empty)
  #[serde(rename = "description")]
  description: Option<String>,
  /// Isilon product name.
  #[serde(rename = "product")]
  product: Option<String>,
  /// Serial number of this node.
  #[serde(rename = "serial_number")]
  serial_number: Option<String>,
  /// Availability of the node.
  #[serde(rename = "status")]
  status: Option<String>,
  /// OneFS build version running on the node.
  #[serde(rename = "version")]
  version: Option<String>
}

impl ClusterNodesAvailableNode {
  pub fn new() -> ClusterNodesAvailableNode {
    ClusterNodesAvailableNode {
      configuration_id: None,
      description: None,
      product: None,
      serial_number: None,
      status: None,
      version: None
    }
  }

  pub fn set_configuration_id(&mut self, configuration_id: String) {
    self.configuration_id = Some(configuration_id);
  }

  pub fn with_configuration_id(mut self, configuration_id: String) -> ClusterNodesAvailableNode {
    self.configuration_id = Some(configuration_id);
    self
  }

  pub fn configuration_id(&self) -> Option<&String> {
    self.configuration_id.as_ref()
  }

  pub fn reset_configuration_id(&mut self) {
    self.configuration_id = None;
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> ClusterNodesAvailableNode {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_product(&mut self, product: String) {
    self.product = Some(product);
  }

  pub fn with_product(mut self, product: String) -> ClusterNodesAvailableNode {
    self.product = Some(product);
    self
  }

  pub fn product(&self) -> Option<&String> {
    self.product.as_ref()
  }

  pub fn reset_product(&mut self) {
    self.product = None;
  }

  pub fn set_serial_number(&mut self, serial_number: String) {
    self.serial_number = Some(serial_number);
  }

  pub fn with_serial_number(mut self, serial_number: String) -> ClusterNodesAvailableNode {
    self.serial_number = Some(serial_number);
    self
  }

  pub fn serial_number(&self) -> Option<&String> {
    self.serial_number.as_ref()
  }

  pub fn reset_serial_number(&mut self) {
    self.serial_number = None;
  }

  pub fn set_status(&mut self, status: String) {
    self.status = Some(status);
  }

  pub fn with_status(mut self, status: String) -> ClusterNodesAvailableNode {
    self.status = Some(status);
    self
  }

  pub fn status(&self) -> Option<&String> {
    self.status.as_ref()
  }

  pub fn reset_status(&mut self) {
    self.status = None;
  }

  pub fn set_version(&mut self, version: String) {
    self.version = Some(version);
  }

  pub fn with_version(mut self, version: String) -> ClusterNodesAvailableNode {
    self.version = Some(version);
    self
  }

  pub fn version(&self) -> Option<&String> {
    self.version.as_ref()
  }

  pub fn reset_version(&mut self) {
    self.version = None;
  }

}



