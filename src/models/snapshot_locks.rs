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
pub struct SnapshotLocks {
  #[serde(rename = "locks")]
  locks: Option<Vec<::models::SnapshotLockExtended>>
}

impl SnapshotLocks {
  pub fn new() -> SnapshotLocks {
    SnapshotLocks {
      locks: None
    }
  }

  pub fn set_locks(&mut self, locks: Vec<::models::SnapshotLockExtended>) {
    self.locks = Some(locks);
  }

  pub fn with_locks(mut self, locks: Vec<::models::SnapshotLockExtended>) -> SnapshotLocks {
    self.locks = Some(locks);
    self
  }

  pub fn locks(&self) -> Option<&Vec<::models::SnapshotLockExtended>> {
    self.locks.as_ref()
  }

  pub fn reset_locks(&mut self) {
    self.locks = None;
  }

}



