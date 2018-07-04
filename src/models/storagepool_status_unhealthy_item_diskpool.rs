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
pub struct StoragepoolStatusUnhealthyItemDiskpool {
  /// The drives that are part of this disk pool.
  #[serde(rename = "drives")]
  drives: Vec<::models::StoragepoolStatusUnprovisionedItem>,
  /// The system ID given to the disk pool.
  #[serde(rename = "id")]
  id: i32,
  /// The disk pool name.
  #[serde(rename = "name")]
  name: String,
  /// The system ID of the disk pool's node pool, if it is in a node pool.
  #[serde(rename = "nodepool_id")]
  nodepool_id: Option<i32>,
  /// The protection policy for the disk pool.
  #[serde(rename = "protection_policy")]
  protection_policy: String,
  /// The SSDs that are part of this disk pool.
  #[serde(rename = "ssd_drives")]
  ssd_drives: Vec<::models::StoragepoolStatusUnprovisionedItem>
}

impl StoragepoolStatusUnhealthyItemDiskpool {
  pub fn new(drives: Vec<::models::StoragepoolStatusUnprovisionedItem>, id: i32, name: String, protection_policy: String, ssd_drives: Vec<::models::StoragepoolStatusUnprovisionedItem>) -> StoragepoolStatusUnhealthyItemDiskpool {
    StoragepoolStatusUnhealthyItemDiskpool {
      drives: drives,
      id: id,
      name: name,
      nodepool_id: None,
      protection_policy: protection_policy,
      ssd_drives: ssd_drives
    }
  }

  pub fn set_drives(&mut self, drives: Vec<::models::StoragepoolStatusUnprovisionedItem>) {
    self.drives = drives;
  }

  pub fn with_drives(mut self, drives: Vec<::models::StoragepoolStatusUnprovisionedItem>) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.drives = drives;
    self
  }

  pub fn drives(&self) -> &Vec<::models::StoragepoolStatusUnprovisionedItem> {
    &self.drives
  }


  pub fn set_id(&mut self, id: i32) {
    self.id = id;
  }

  pub fn with_id(mut self, id: i32) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.id = id;
    self
  }

  pub fn id(&self) -> &i32 {
    &self.id
  }


  pub fn set_name(&mut self, name: String) {
    self.name = name;
  }

  pub fn with_name(mut self, name: String) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.name = name;
    self
  }

  pub fn name(&self) -> &String {
    &self.name
  }


  pub fn set_nodepool_id(&mut self, nodepool_id: i32) {
    self.nodepool_id = Some(nodepool_id);
  }

  pub fn with_nodepool_id(mut self, nodepool_id: i32) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.nodepool_id = Some(nodepool_id);
    self
  }

  pub fn nodepool_id(&self) -> Option<&i32> {
    self.nodepool_id.as_ref()
  }

  pub fn reset_nodepool_id(&mut self) {
    self.nodepool_id = None;
  }

  pub fn set_protection_policy(&mut self, protection_policy: String) {
    self.protection_policy = protection_policy;
  }

  pub fn with_protection_policy(mut self, protection_policy: String) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.protection_policy = protection_policy;
    self
  }

  pub fn protection_policy(&self) -> &String {
    &self.protection_policy
  }


  pub fn set_ssd_drives(&mut self, ssd_drives: Vec<::models::StoragepoolStatusUnprovisionedItem>) {
    self.ssd_drives = ssd_drives;
  }

  pub fn with_ssd_drives(mut self, ssd_drives: Vec<::models::StoragepoolStatusUnprovisionedItem>) -> StoragepoolStatusUnhealthyItemDiskpool {
    self.ssd_drives = ssd_drives;
    self
  }

  pub fn ssd_drives(&self) -> &Vec<::models::StoragepoolStatusUnprovisionedItem> {
    &self.ssd_drives
  }


}



