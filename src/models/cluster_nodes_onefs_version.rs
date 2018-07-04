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
pub struct ClusterNodesOnefsVersion {
  #[serde(rename = "bugfix")]
  bugfix: Option<i32>,
  #[serde(rename = "maintenance")]
  maintenance: Option<i32>,
  #[serde(rename = "major")]
  major: Option<i32>,
  #[serde(rename = "minor")]
  minor: Option<i32>,
  /// hex representation of the OneFS version integer.
  #[serde(rename = "version")]
  version: Option<String>
}

impl ClusterNodesOnefsVersion {
  pub fn new() -> ClusterNodesOnefsVersion {
    ClusterNodesOnefsVersion {
      bugfix: None,
      maintenance: None,
      major: None,
      minor: None,
      version: None
    }
  }

  pub fn set_bugfix(&mut self, bugfix: i32) {
    self.bugfix = Some(bugfix);
  }

  pub fn with_bugfix(mut self, bugfix: i32) -> ClusterNodesOnefsVersion {
    self.bugfix = Some(bugfix);
    self
  }

  pub fn bugfix(&self) -> Option<&i32> {
    self.bugfix.as_ref()
  }

  pub fn reset_bugfix(&mut self) {
    self.bugfix = None;
  }

  pub fn set_maintenance(&mut self, maintenance: i32) {
    self.maintenance = Some(maintenance);
  }

  pub fn with_maintenance(mut self, maintenance: i32) -> ClusterNodesOnefsVersion {
    self.maintenance = Some(maintenance);
    self
  }

  pub fn maintenance(&self) -> Option<&i32> {
    self.maintenance.as_ref()
  }

  pub fn reset_maintenance(&mut self) {
    self.maintenance = None;
  }

  pub fn set_major(&mut self, major: i32) {
    self.major = Some(major);
  }

  pub fn with_major(mut self, major: i32) -> ClusterNodesOnefsVersion {
    self.major = Some(major);
    self
  }

  pub fn major(&self) -> Option<&i32> {
    self.major.as_ref()
  }

  pub fn reset_major(&mut self) {
    self.major = None;
  }

  pub fn set_minor(&mut self, minor: i32) {
    self.minor = Some(minor);
  }

  pub fn with_minor(mut self, minor: i32) -> ClusterNodesOnefsVersion {
    self.minor = Some(minor);
    self
  }

  pub fn minor(&self) -> Option<&i32> {
    self.minor.as_ref()
  }

  pub fn reset_minor(&mut self) {
    self.minor = None;
  }

  pub fn set_version(&mut self, version: String) {
    self.version = Some(version);
  }

  pub fn with_version(mut self, version: String) -> ClusterNodesOnefsVersion {
    self.version = Some(version);
    self
  }

  pub fn version(&self) -> Option<&String> {
    self.version.as_ref()
  }

  pub fn reset_version(&mut self) {
    self.version = None;
  }

}



