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
pub struct ProvidersSummaryProviderInstance {
  #[serde(rename = "active_server")]
  active_server: Option<String>,
  #[serde(rename = "client_site")]
  client_site: Option<String>,
  #[serde(rename = "connections")]
  connections: Option<Vec<::models::ProvidersSummaryProviderInstanceConnection>>,
  #[serde(rename = "dc_site")]
  dc_site: Option<String>,
  #[serde(rename = "forest")]
  forest: Option<String>,
  #[serde(rename = "groupnet")]
  groupnet: Option<String>,
  /// Specifies the ID of the provider.
  #[serde(rename = "id")]
  id: Option<String>,
  /// Specifies the name of the provider.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Indicates the status of the provider.
  #[serde(rename = "status")]
  status: Option<String>,
  /// Specifies the type of provider.
  #[serde(rename = "type")]
  _type: Option<String>
}

impl ProvidersSummaryProviderInstance {
  pub fn new() -> ProvidersSummaryProviderInstance {
    ProvidersSummaryProviderInstance {
      active_server: None,
      client_site: None,
      connections: None,
      dc_site: None,
      forest: None,
      groupnet: None,
      id: None,
      name: None,
      status: None,
      _type: None
    }
  }

  pub fn set_active_server(&mut self, active_server: String) {
    self.active_server = Some(active_server);
  }

  pub fn with_active_server(mut self, active_server: String) -> ProvidersSummaryProviderInstance {
    self.active_server = Some(active_server);
    self
  }

  pub fn active_server(&self) -> Option<&String> {
    self.active_server.as_ref()
  }

  pub fn reset_active_server(&mut self) {
    self.active_server = None;
  }

  pub fn set_client_site(&mut self, client_site: String) {
    self.client_site = Some(client_site);
  }

  pub fn with_client_site(mut self, client_site: String) -> ProvidersSummaryProviderInstance {
    self.client_site = Some(client_site);
    self
  }

  pub fn client_site(&self) -> Option<&String> {
    self.client_site.as_ref()
  }

  pub fn reset_client_site(&mut self) {
    self.client_site = None;
  }

  pub fn set_connections(&mut self, connections: Vec<::models::ProvidersSummaryProviderInstanceConnection>) {
    self.connections = Some(connections);
  }

  pub fn with_connections(mut self, connections: Vec<::models::ProvidersSummaryProviderInstanceConnection>) -> ProvidersSummaryProviderInstance {
    self.connections = Some(connections);
    self
  }

  pub fn connections(&self) -> Option<&Vec<::models::ProvidersSummaryProviderInstanceConnection>> {
    self.connections.as_ref()
  }

  pub fn reset_connections(&mut self) {
    self.connections = None;
  }

  pub fn set_dc_site(&mut self, dc_site: String) {
    self.dc_site = Some(dc_site);
  }

  pub fn with_dc_site(mut self, dc_site: String) -> ProvidersSummaryProviderInstance {
    self.dc_site = Some(dc_site);
    self
  }

  pub fn dc_site(&self) -> Option<&String> {
    self.dc_site.as_ref()
  }

  pub fn reset_dc_site(&mut self) {
    self.dc_site = None;
  }

  pub fn set_forest(&mut self, forest: String) {
    self.forest = Some(forest);
  }

  pub fn with_forest(mut self, forest: String) -> ProvidersSummaryProviderInstance {
    self.forest = Some(forest);
    self
  }

  pub fn forest(&self) -> Option<&String> {
    self.forest.as_ref()
  }

  pub fn reset_forest(&mut self) {
    self.forest = None;
  }

  pub fn set_groupnet(&mut self, groupnet: String) {
    self.groupnet = Some(groupnet);
  }

  pub fn with_groupnet(mut self, groupnet: String) -> ProvidersSummaryProviderInstance {
    self.groupnet = Some(groupnet);
    self
  }

  pub fn groupnet(&self) -> Option<&String> {
    self.groupnet.as_ref()
  }

  pub fn reset_groupnet(&mut self) {
    self.groupnet = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> ProvidersSummaryProviderInstance {
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

  pub fn with_name(mut self, name: String) -> ProvidersSummaryProviderInstance {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_status(&mut self, status: String) {
    self.status = Some(status);
  }

  pub fn with_status(mut self, status: String) -> ProvidersSummaryProviderInstance {
    self.status = Some(status);
    self
  }

  pub fn status(&self) -> Option<&String> {
    self.status.as_ref()
  }

  pub fn reset_status(&mut self) {
    self.status = None;
  }

  pub fn set__type(&mut self, _type: String) {
    self._type = Some(_type);
  }

  pub fn with__type(mut self, _type: String) -> ProvidersSummaryProviderInstance {
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



