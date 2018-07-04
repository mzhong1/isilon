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
pub struct PoolsPoolInterfacesInterface {
  /// Unique interface ID.
  #[serde(rename = "id")]
  id: String,
  /// List of IP addresses
  #[serde(rename = "ip_addrs")]
  ip_addrs: Vec<String>,
  /// Logical Node Number
  #[serde(rename = "lnn")]
  lnn: i32,
  /// The name of the interface.
  #[serde(rename = "name")]
  name: String,
  /// NIC name
  #[serde(rename = "nic_name")]
  nic_name: String,
  /// List of owners (membership)
  #[serde(rename = "owners")]
  owners: Vec<::models::PoolsPoolInterfacesInterfaceOwner>,
  /// Status of the interface
  #[serde(rename = "status")]
  status: String,
  /// Interface type.  The '*gige' types stand for 'gigabit ethernet'.  'gige' itself is occasionally also referred to in other places as 'ext' for 'external'.  'ib' and 'ib_qdr' are internal Infiniband interface types.  'vlan' and 'vmxnet3' are virtual interface types that appear on virtual nodes.  'loopback' is an interface for failover addresses and should only appear if failover is configured.
  #[serde(rename = "type")]
  _type: String
}

impl PoolsPoolInterfacesInterface {
  pub fn new(id: String, ip_addrs: Vec<String>, lnn: i32, name: String, nic_name: String, owners: Vec<::models::PoolsPoolInterfacesInterfaceOwner>, status: String, _type: String) -> PoolsPoolInterfacesInterface {
    PoolsPoolInterfacesInterface {
      id: id,
      ip_addrs: ip_addrs,
      lnn: lnn,
      name: name,
      nic_name: nic_name,
      owners: owners,
      status: status,
      _type: _type
    }
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> PoolsPoolInterfacesInterface {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


  pub fn set_ip_addrs(&mut self, ip_addrs: Vec<String>) {
    self.ip_addrs = ip_addrs;
  }

  pub fn with_ip_addrs(mut self, ip_addrs: Vec<String>) -> PoolsPoolInterfacesInterface {
    self.ip_addrs = ip_addrs;
    self
  }

  pub fn ip_addrs(&self) -> &Vec<String> {
    &self.ip_addrs
  }


  pub fn set_lnn(&mut self, lnn: i32) {
    self.lnn = lnn;
  }

  pub fn with_lnn(mut self, lnn: i32) -> PoolsPoolInterfacesInterface {
    self.lnn = lnn;
    self
  }

  pub fn lnn(&self) -> &i32 {
    &self.lnn
  }


  pub fn set_name(&mut self, name: String) {
    self.name = name;
  }

  pub fn with_name(mut self, name: String) -> PoolsPoolInterfacesInterface {
    self.name = name;
    self
  }

  pub fn name(&self) -> &String {
    &self.name
  }


  pub fn set_nic_name(&mut self, nic_name: String) {
    self.nic_name = nic_name;
  }

  pub fn with_nic_name(mut self, nic_name: String) -> PoolsPoolInterfacesInterface {
    self.nic_name = nic_name;
    self
  }

  pub fn nic_name(&self) -> &String {
    &self.nic_name
  }


  pub fn set_owners(&mut self, owners: Vec<::models::PoolsPoolInterfacesInterfaceOwner>) {
    self.owners = owners;
  }

  pub fn with_owners(mut self, owners: Vec<::models::PoolsPoolInterfacesInterfaceOwner>) -> PoolsPoolInterfacesInterface {
    self.owners = owners;
    self
  }

  pub fn owners(&self) -> &Vec<::models::PoolsPoolInterfacesInterfaceOwner> {
    &self.owners
  }


  pub fn set_status(&mut self, status: String) {
    self.status = status;
  }

  pub fn with_status(mut self, status: String) -> PoolsPoolInterfacesInterface {
    self.status = status;
    self
  }

  pub fn status(&self) -> &String {
    &self.status
  }


  pub fn set__type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with__type(mut self, _type: String) -> PoolsPoolInterfacesInterface {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


}



