

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatusBatterystatusNode {
  /// Error message, if the HTTP status returned from this node was not 200.
  #[serde(rename = "error")]
  error: Option<String>,
  /// Node ID of the node reporting this information.
  #[serde(rename = "id")]
  id: Option<i32>,
  /// The last battery test time for battery 1.
  #[serde(rename = "last_test_time1")]
  last_test_time1: Option<String>,
  /// The last battery test time for battery 2.
  #[serde(rename = "last_test_time2")]
  last_test_time2: Option<String>,
  /// Logical node number of the node reporting this information.
  #[serde(rename = "lnn")]
  lnn: Option<i32>,
  /// The next checkup for battery 1.
  #[serde(rename = "next_test_time1")]
  next_test_time1: Option<String>,
  /// The next checkup for battery 2.
  #[serde(rename = "next_test_time2")]
  next_test_time2: Option<String>,
  /// Node has battery status.
  #[serde(rename = "present")]
  present: Option<bool>,
  /// The result of the last battery test for battery 1.
  #[serde(rename = "result1")]
  result1: Option<String>,
  /// The result of the last battery test for battery 2.
  #[serde(rename = "result2")]
  result2: Option<String>,
  /// Status of the HTTP response from this node if not 200.  If 200, this field does not appear.
  #[serde(rename = "status")]
  status: Option<i32>,
  /// The status of battery 1.
  #[serde(rename = "status1")]
  status1: Option<String>,
  /// The status of battery 2.
  #[serde(rename = "status2")]
  status2: Option<String>,
  /// Node supports battery status.
  #[serde(rename = "supported")]
  supported: Option<bool>
}

