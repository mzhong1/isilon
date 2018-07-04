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
pub struct MappingUsersRulesRuleUser1 {
  #[serde(rename = "domain")]
  domain: Option<String>,
  #[serde(rename = "user")]
  user: String
}

impl MappingUsersRulesRuleUser1 {
  pub fn new(user: String) -> MappingUsersRulesRuleUser1 {
    MappingUsersRulesRuleUser1 {
      domain: None,
      user: user
    }
  }

  pub fn set_domain(&mut self, domain: String) {
    self.domain = Some(domain);
  }

  pub fn with_domain(mut self, domain: String) -> MappingUsersRulesRuleUser1 {
    self.domain = Some(domain);
    self
  }

  pub fn domain(&self) -> Option<&String> {
    self.domain.as_ref()
  }

  pub fn reset_domain(&mut self) {
    self.domain = None;
  }

  pub fn set_user(&mut self, user: String) {
    self.user = user;
  }

  pub fn with_user(mut self, user: String) -> MappingUsersRulesRuleUser1 {
    self.user = user;
    self
  }

  pub fn user(&self) -> &String {
    &self.user
  }


}



