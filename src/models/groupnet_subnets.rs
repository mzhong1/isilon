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
pub struct GroupnetSubnets {
  #[serde(rename = "subnets")]
  subnets: Option<Vec<::models::GroupnetSubnetExtended>>
}

impl GroupnetSubnets {
  pub fn new() -> GroupnetSubnets {
    GroupnetSubnets {
      subnets: None
    }
  }

  pub fn set_subnets(&mut self, subnets: Vec<::models::GroupnetSubnetExtended>) {
    self.subnets = Some(subnets);
  }

  pub fn with_subnets(mut self, subnets: Vec<::models::GroupnetSubnetExtended>) -> GroupnetSubnets {
    self.subnets = Some(subnets);
    self
  }

  pub fn subnets(&self) -> Option<&Vec<::models::GroupnetSubnetExtended>> {
    self.subnets.as_ref()
  }

  pub fn reset_subnets(&mut self) {
    self.subnets = None;
  }

}



