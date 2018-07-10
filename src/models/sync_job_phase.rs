

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncJobPhase {
  /// The time the job ended this phase.
  #[serde(rename = "end_time")]
  end_time: Option<i32>,
  /// The phase that the job was in.
  #[serde(rename = "phase")]
  phase: Option<String>,
  /// The time the job began this phase.
  #[serde(rename = "start_time")]
  start_time: Option<i32>
}

