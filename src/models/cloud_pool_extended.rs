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
pub struct CloudPoolExtended {
  /// A list of valid names for the accounts in this pool.  There is currently only one account allowed per pool.
  #[serde(rename = "accounts")]
  accounts: Option<Vec<String>>,
  /// The guid of the cluster where this pool was created
  #[serde(rename = "birth_cluster_id")]
  birth_cluster_id: Option<String>,
  /// A brief description of this pool
  #[serde(rename = "description")]
  description: Option<String>,
  /// A unique name for this pool
  #[serde(rename = "name")]
  name: Option<String>,
  /// A string identifier of the cloud services vendor
  #[serde(rename = "vendor")]
  vendor: Option<String>,
  /// A unique name for this pool
  #[serde(rename = "id")]
  id: Option<String>,
  /// Indicates whether this pool is in a good state (\"OK\") or disabled (\"disabled\")
  #[serde(rename = "state")]
  state: Option<String>,
  /// Gives further information to describe the state of this pool
  #[serde(rename = "state_details")]
  state_details: Option<String>,
  /// The type of cloud protocol required.  E.g., \"isilon\" for EMC Isilon, \"ecs\" for EMC ECS Appliance, \"virtustream\" for Virtustream Storage Cloud, \"azure\" for Microsoft Azure and \"s3\" for Amazon S3
  #[serde(rename = "type")]
  _type: Option<String>
}

impl CloudPoolExtended {
  pub fn new() -> CloudPoolExtended {
    CloudPoolExtended {
      accounts: None,
      birth_cluster_id: None,
      description: None,
      name: None,
      vendor: None,
      id: None,
      state: None,
      state_details: None,
      _type: None
    }
  }

  pub fn set_accounts(&mut self, accounts: Vec<String>) {
    self.accounts = Some(accounts);
  }

  pub fn with_accounts(mut self, accounts: Vec<String>) -> CloudPoolExtended {
    self.accounts = Some(accounts);
    self
  }

  pub fn accounts(&self) -> Option<&Vec<String>> {
    self.accounts.as_ref()
  }

  pub fn reset_accounts(&mut self) {
    self.accounts = None;
  }

  pub fn set_birth_cluster_id(&mut self, birth_cluster_id: String) {
    self.birth_cluster_id = Some(birth_cluster_id);
  }

  pub fn with_birth_cluster_id(mut self, birth_cluster_id: String) -> CloudPoolExtended {
    self.birth_cluster_id = Some(birth_cluster_id);
    self
  }

  pub fn birth_cluster_id(&self) -> Option<&String> {
    self.birth_cluster_id.as_ref()
  }

  pub fn reset_birth_cluster_id(&mut self) {
    self.birth_cluster_id = None;
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> CloudPoolExtended {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> CloudPoolExtended {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_vendor(&mut self, vendor: String) {
    self.vendor = Some(vendor);
  }

  pub fn with_vendor(mut self, vendor: String) -> CloudPoolExtended {
    self.vendor = Some(vendor);
    self
  }

  pub fn vendor(&self) -> Option<&String> {
    self.vendor.as_ref()
  }

  pub fn reset_vendor(&mut self) {
    self.vendor = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> CloudPoolExtended {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_state(&mut self, state: String) {
    self.state = Some(state);
  }

  pub fn with_state(mut self, state: String) -> CloudPoolExtended {
    self.state = Some(state);
    self
  }

  pub fn state(&self) -> Option<&String> {
    self.state.as_ref()
  }

  pub fn reset_state(&mut self) {
    self.state = None;
  }

  pub fn set_state_details(&mut self, state_details: String) {
    self.state_details = Some(state_details);
  }

  pub fn with_state_details(mut self, state_details: String) -> CloudPoolExtended {
    self.state_details = Some(state_details);
    self
  }

  pub fn state_details(&self) -> Option<&String> {
    self.state_details.as_ref()
  }

  pub fn reset_state_details(&mut self) {
    self.state_details = None;
  }

  pub fn set__type(&mut self, _type: String) {
    self._type = Some(_type);
  }

  pub fn with__type(mut self, _type: String) -> CloudPoolExtended {
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



