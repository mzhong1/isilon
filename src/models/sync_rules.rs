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
pub struct SyncRules {
  #[serde(rename = "rules")]
  rules: Option<Vec<::models::SyncRuleExtended>>
}

impl SyncRules {
  pub fn new() -> SyncRules {
    SyncRules {
      rules: None
    }
  }

  pub fn set_rules(&mut self, rules: Vec<::models::SyncRuleExtended>) {
    self.rules = Some(rules);
  }

  pub fn with_rules(mut self, rules: Vec<::models::SyncRuleExtended>) -> SyncRules {
    self.rules = Some(rules);
    self
  }

  pub fn rules(&self) -> Option<&Vec<::models::SyncRuleExtended>> {
    self.rules.as_ref()
  }

  pub fn reset_rules(&mut self) {
    self.rules = None;
  }

}



