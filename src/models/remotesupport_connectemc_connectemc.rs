

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct RemotesupportConnectemcConnectemc {
  /// Email the customer if all transmission methods fail.
  #[serde(rename = "email_customer_on_failure")]
  email_customer_on_failure: Option<bool>,
  /// Enable ConnectEMC.
  #[serde(rename = "enabled")]
  enabled: Option<bool>,
  /// List of network pools that are able to connect to the ESRS gateway.  Necessary to enable ConnectEMC.
  #[serde(rename = "gateway_access_pools")]
  gateway_access_pools: Option<Vec<String>>,
  /// Primary ESRS Gateway. Necessary to enable ConnectEMC.
  #[serde(rename = "primary_esrs_gateway")]
  primary_esrs_gateway: Option<String>,
  /// Secondary ESRS Gateway. Used if Primary is unavailable.
  #[serde(rename = "secondary_esrs_gateway")]
  secondary_esrs_gateway: Option<String>,
  /// Use SMPT if primary and secondary gateways are unavailable.
  #[serde(rename = "use_smtp_failover")]
  use_smtp_failover: Option<bool>
}

