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
pub struct MappingUsersRulesRule {
  /// Specifies the operator to make rules on specified users or groups.
  #[serde(rename = "operator")]
  operator: Option<String>,
  /// Specifies the properties for user mapping rules.
  #[serde(rename = "options")]
  options: Option<::models::MappingUsersRulesRuleOptions>,
  /// 
  #[serde(rename = "user1")]
  user1: Option<::models::MappingUsersRulesRuleUser2>,
  /// 
  #[serde(rename = "user2")]
  user2: Option<::models::MappingUsersRulesRuleUser2>
}

impl MappingUsersRulesRule {
  pub fn new() -> MappingUsersRulesRule {
    MappingUsersRulesRule {
      operator: None,
      options: None,
      user1: None,
      user2: None
    }
  }

  pub fn set_operator(&mut self, operator: String) {
    self.operator = Some(operator);
  }

  pub fn with_operator(mut self, operator: String) -> MappingUsersRulesRule {
    self.operator = Some(operator);
    self
  }

  pub fn operator(&self) -> Option<&String> {
    self.operator.as_ref()
  }

  pub fn reset_operator(&mut self) {
    self.operator = None;
  }

  pub fn set_options(&mut self, options: ::models::MappingUsersRulesRuleOptions) {
    self.options = Some(options);
  }

  pub fn with_options(mut self, options: ::models::MappingUsersRulesRuleOptions) -> MappingUsersRulesRule {
    self.options = Some(options);
    self
  }

  pub fn options(&self) -> Option<&::models::MappingUsersRulesRuleOptions> {
    self.options.as_ref()
  }

  pub fn reset_options(&mut self) {
    self.options = None;
  }

  pub fn set_user1(&mut self, user1: ::models::MappingUsersRulesRuleUser2) {
    self.user1 = Some(user1);
  }

  pub fn with_user1(mut self, user1: ::models::MappingUsersRulesRuleUser2) -> MappingUsersRulesRule {
    self.user1 = Some(user1);
    self
  }

  pub fn user1(&self) -> Option<&::models::MappingUsersRulesRuleUser2> {
    self.user1.as_ref()
  }

  pub fn reset_user1(&mut self) {
    self.user1 = None;
  }

  pub fn set_user2(&mut self, user2: ::models::MappingUsersRulesRuleUser2) {
    self.user2 = Some(user2);
  }

  pub fn with_user2(mut self, user2: ::models::MappingUsersRulesRuleUser2) -> MappingUsersRulesRule {
    self.user2 = Some(user2);
    self
  }

  pub fn user2(&self) -> Option<&::models::MappingUsersRulesRuleUser2> {
    self.user2.as_ref()
  }

  pub fn reset_user2(&mut self) {
    self.user2 = None;
  }

}



