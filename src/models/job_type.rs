

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JobType {
  /// Whether the job type is enabled and able to run.
  #[serde(rename = "enabled")]
  enabled: Option<bool>,
  /// Default impact policy of this job type.
  #[serde(rename = "policy")]
  policy: Option<String>,
  /// Default priority of this job type; lower numbers preempt higher numbers.
  #[serde(rename = "priority")]
  priority: Option<i32>,
  /// The schedule on which this job type is queued, if any.
  #[serde(rename = "schedule")]
  schedule: Option<String>
}

