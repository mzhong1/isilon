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
pub struct MappingUsersRulesRuleUser2 {
  #[serde(rename = "domain")]
  domain: Option<String>,
  #[serde(rename = "user")]
  user: Option<String>
}

impl MappingUsersRulesRuleUser2 {
  pub fn new() -> MappingUsersRulesRuleUser2 {
    MappingUsersRulesRuleUser2 {
      domain: None,
      user: None
    }
  }

  pub fn set_domain(&mut self, domain: String) {
    self.domain = Some(domain);
  }

  pub fn with_domain(mut self, domain: String) -> MappingUsersRulesRuleUser2 {
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
    self.user = Some(user);
  }

  pub fn with_user(mut self, user: String) -> MappingUsersRulesRuleUser2 {
    self.user = Some(user);
    self
  }

  pub fn user(&self) -> Option<&String> {
    self.user.as_ref()
  }

  pub fn reset_user(&mut self) {
    self.user = None;
  }

}



