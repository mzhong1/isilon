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
pub struct NodePartitionsNodePartition {
  /// The block size used for the reported partition information.
  #[serde(rename = "block_size")]
  block_size: Option<i32>,
  /// Total blocks on this file system partition.
  #[serde(rename = "capacity")]
  capacity: Option<i32>,
  /// Comma separated list of devices used for this file system partition.
  #[serde(rename = "component_devices")]
  component_devices: Option<String>,
  /// Directory on which this partition is mounted.
  #[serde(rename = "mount_point")]
  mount_point: Option<String>,
  /// Used blocks on this file system partition, expressed as a percentage.
  #[serde(rename = "percent_used")]
  percent_used: Option<String>,
  /// System partition details as provided by statfs(2).
  #[serde(rename = "statfs")]
  statfs: Option<::models::NodePartitionsNodePartitionStatfs>,
  /// Used blocks on this file system partition.
  #[serde(rename = "used")]
  used: Option<i32>
}

impl NodePartitionsNodePartition {
  pub fn new() -> NodePartitionsNodePartition {
    NodePartitionsNodePartition {
      block_size: None,
      capacity: None,
      component_devices: None,
      mount_point: None,
      percent_used: None,
      statfs: None,
      used: None
    }
  }

  pub fn set_block_size(&mut self, block_size: i32) {
    self.block_size = Some(block_size);
  }

  pub fn with_block_size(mut self, block_size: i32) -> NodePartitionsNodePartition {
    self.block_size = Some(block_size);
    self
  }

  pub fn block_size(&self) -> Option<&i32> {
    self.block_size.as_ref()
  }

  pub fn reset_block_size(&mut self) {
    self.block_size = None;
  }

  pub fn set_capacity(&mut self, capacity: i32) {
    self.capacity = Some(capacity);
  }

  pub fn with_capacity(mut self, capacity: i32) -> NodePartitionsNodePartition {
    self.capacity = Some(capacity);
    self
  }

  pub fn capacity(&self) -> Option<&i32> {
    self.capacity.as_ref()
  }

  pub fn reset_capacity(&mut self) {
    self.capacity = None;
  }

  pub fn set_component_devices(&mut self, component_devices: String) {
    self.component_devices = Some(component_devices);
  }

  pub fn with_component_devices(mut self, component_devices: String) -> NodePartitionsNodePartition {
    self.component_devices = Some(component_devices);
    self
  }

  pub fn component_devices(&self) -> Option<&String> {
    self.component_devices.as_ref()
  }

  pub fn reset_component_devices(&mut self) {
    self.component_devices = None;
  }

  pub fn set_mount_point(&mut self, mount_point: String) {
    self.mount_point = Some(mount_point);
  }

  pub fn with_mount_point(mut self, mount_point: String) -> NodePartitionsNodePartition {
    self.mount_point = Some(mount_point);
    self
  }

  pub fn mount_point(&self) -> Option<&String> {
    self.mount_point.as_ref()
  }

  pub fn reset_mount_point(&mut self) {
    self.mount_point = None;
  }

  pub fn set_percent_used(&mut self, percent_used: String) {
    self.percent_used = Some(percent_used);
  }

  pub fn with_percent_used(mut self, percent_used: String) -> NodePartitionsNodePartition {
    self.percent_used = Some(percent_used);
    self
  }

  pub fn percent_used(&self) -> Option<&String> {
    self.percent_used.as_ref()
  }

  pub fn reset_percent_used(&mut self) {
    self.percent_used = None;
  }

  pub fn set_statfs(&mut self, statfs: ::models::NodePartitionsNodePartitionStatfs) {
    self.statfs = Some(statfs);
  }

  pub fn with_statfs(mut self, statfs: ::models::NodePartitionsNodePartitionStatfs) -> NodePartitionsNodePartition {
    self.statfs = Some(statfs);
    self
  }

  pub fn statfs(&self) -> Option<&::models::NodePartitionsNodePartitionStatfs> {
    self.statfs.as_ref()
  }

  pub fn reset_statfs(&mut self) {
    self.statfs = None;
  }

  pub fn set_used(&mut self, used: i32) {
    self.used = Some(used);
  }

  pub fn with_used(mut self, used: i32) -> NodePartitionsNodePartition {
    self.used = Some(used);
    self
  }

  pub fn used(&self) -> Option<&i32> {
    self.used.as_ref()
  }

  pub fn reset_used(&mut self) {
    self.used = None;
  }

}



