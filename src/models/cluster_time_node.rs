

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterTimeNode {
  /// Error message, if the HTTP status returned from this node was not 200.
  #[serde(rename = "error")]
  error: Option<String>,
  /// Node ID of the node reporting this information.
  #[serde(rename = "id")]
  id: Option<i32>,
  /// Logical node number of the node reporting this information.
  #[serde(rename = "lnn")]
  lnn: Option<i32>,
  /// Status of the HTTP response from this node if not 200.  If 200, this field does not appear.
  #[serde(rename = "status")]
  status: Option<i32>,
  /// The current time on the cluster as a UNIX epoch (seconds since 1/1/1970), as reported by this node.
  #[serde(rename = "time")]
  time: Option<i32>
}

