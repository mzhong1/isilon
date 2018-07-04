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
pub struct StoragepoolTiersExtended {
  #[serde(rename = "tiers")]
  tiers: Option<Vec<::models::StoragepoolTierExtended>>,
  /// Total number of items available.
  #[serde(rename = "total")]
  total: Option<i32>
}

impl StoragepoolTiersExtended {
  pub fn new() -> StoragepoolTiersExtended {
    StoragepoolTiersExtended {
      tiers: None,
      total: None
    }
  }

  pub fn set_tiers(&mut self, tiers: Vec<::models::StoragepoolTierExtended>) {
    self.tiers = Some(tiers);
  }

  pub fn with_tiers(mut self, tiers: Vec<::models::StoragepoolTierExtended>) -> StoragepoolTiersExtended {
    self.tiers = Some(tiers);
    self
  }

  pub fn tiers(&self) -> Option<&Vec<::models::StoragepoolTierExtended>> {
    self.tiers.as_ref()
  }

  pub fn reset_tiers(&mut self) {
    self.tiers = None;
  }

  pub fn set_total(&mut self, total: i32) {
    self.total = Some(total);
  }

  pub fn with_total(mut self, total: i32) -> StoragepoolTiersExtended {
    self.total = Some(total);
    self
  }

  pub fn total(&self) -> Option<&i32> {
    self.total.as_ref()
  }

  pub fn reset_total(&mut self) {
    self.total = None;
  }

}



