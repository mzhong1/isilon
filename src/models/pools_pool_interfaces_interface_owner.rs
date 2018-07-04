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
pub struct PoolsPoolInterfacesInterfaceOwner {
  #[serde(rename = "groupnet")]
  groupnet: Option<String>,
  #[serde(rename = "pool")]
  pool: Option<String>,
  #[serde(rename = "subnet")]
  subnet: Option<String>
}

impl PoolsPoolInterfacesInterfaceOwner {
  pub fn new() -> PoolsPoolInterfacesInterfaceOwner {
    PoolsPoolInterfacesInterfaceOwner {
      groupnet: None,
      pool: None,
      subnet: None
    }
  }

  pub fn set_groupnet(&mut self, groupnet: String) {
    self.groupnet = Some(groupnet);
  }

  pub fn with_groupnet(mut self, groupnet: String) -> PoolsPoolInterfacesInterfaceOwner {
    self.groupnet = Some(groupnet);
    self
  }

  pub fn groupnet(&self) -> Option<&String> {
    self.groupnet.as_ref()
  }

  pub fn reset_groupnet(&mut self) {
    self.groupnet = None;
  }

  pub fn set_pool(&mut self, pool: String) {
    self.pool = Some(pool);
  }

  pub fn with_pool(mut self, pool: String) -> PoolsPoolInterfacesInterfaceOwner {
    self.pool = Some(pool);
    self
  }

  pub fn pool(&self) -> Option<&String> {
    self.pool.as_ref()
  }

  pub fn reset_pool(&mut self) {
    self.pool = None;
  }

  pub fn set_subnet(&mut self, subnet: String) {
    self.subnet = Some(subnet);
  }

  pub fn with_subnet(mut self, subnet: String) -> PoolsPoolInterfacesInterfaceOwner {
    self.subnet = Some(subnet);
    self
  }

  pub fn subnet(&self) -> Option<&String> {
    self.subnet.as_ref()
  }

  pub fn reset_subnet(&mut self) {
    self.subnet = None;
  }

}



