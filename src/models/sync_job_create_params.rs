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
pub struct SyncJobCreateParams {
  /// The action to be taken by this job.
  #[serde(rename = "action")]
  action: Option<String>,
  /// The ID or Name of the policy
  #[serde(rename = "id")]
  id: String,
  /// Only valid for allow_write, and allow_write_revert; specify the desired logging level, will be stored in the logs for isi_migrate, defaults to 'info'.
  #[serde(rename = "log_level")]
  log_level: Option<String>,
  /// An optional snapshot to copy/sync from.
  #[serde(rename = "source_snapshot")]
  source_snapshot: Option<String>,
  /// Only valid for allow_write, and allow_write_revert; specify the desired workers per node, defaults to 3.
  #[serde(rename = "workers_per_node")]
  workers_per_node: Option<i32>
}

impl SyncJobCreateParams {
  pub fn new(id: String) -> SyncJobCreateParams {
    SyncJobCreateParams {
      action: None,
      id: id,
      log_level: None,
      source_snapshot: None,
      workers_per_node: None
    }
  }

  pub fn set_action(&mut self, action: String) {
    self.action = Some(action);
  }

  pub fn with_action(mut self, action: String) -> SyncJobCreateParams {
    self.action = Some(action);
    self
  }

  pub fn action(&self) -> Option<&String> {
    self.action.as_ref()
  }

  pub fn reset_action(&mut self) {
    self.action = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> SyncJobCreateParams {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


  pub fn set_log_level(&mut self, log_level: String) {
    self.log_level = Some(log_level);
  }

  pub fn with_log_level(mut self, log_level: String) -> SyncJobCreateParams {
    self.log_level = Some(log_level);
    self
  }

  pub fn log_level(&self) -> Option<&String> {
    self.log_level.as_ref()
  }

  pub fn reset_log_level(&mut self) {
    self.log_level = None;
  }

  pub fn set_source_snapshot(&mut self, source_snapshot: String) {
    self.source_snapshot = Some(source_snapshot);
  }

  pub fn with_source_snapshot(mut self, source_snapshot: String) -> SyncJobCreateParams {
    self.source_snapshot = Some(source_snapshot);
    self
  }

  pub fn source_snapshot(&self) -> Option<&String> {
    self.source_snapshot.as_ref()
  }

  pub fn reset_source_snapshot(&mut self) {
    self.source_snapshot = None;
  }

  pub fn set_workers_per_node(&mut self, workers_per_node: i32) {
    self.workers_per_node = Some(workers_per_node);
  }

  pub fn with_workers_per_node(mut self, workers_per_node: i32) -> SyncJobCreateParams {
    self.workers_per_node = Some(workers_per_node);
    self
  }

  pub fn workers_per_node(&self) -> Option<&i32> {
    self.workers_per_node.as_ref()
  }

  pub fn reset_workers_per_node(&mut self) {
    self.workers_per_node = None;
  }

}



