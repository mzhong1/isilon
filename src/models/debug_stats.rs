/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// DebugStats : Statistics for all the methods of all URIs in the Platform API.

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugStats {
  /// Per-method statistics.
  #[serde(rename = "DESCRIBE")]
  DESCRIBE: Option<::models::DebugStatsUnknown>,
  /// Per-method statistics.
  #[serde(rename = "UNKNOWN")]
  UNKNOWN: Option<::models::DebugStatsUnknown>,
  #[serde(rename = "handlers")]
  handlers: Option<Vec<::models::DebugStatsHandler>>
}

impl DebugStats {
  /// Statistics for all the methods of all URIs in the Platform API.
  pub fn new() -> DebugStats {
    DebugStats {
      DESCRIBE: None,
      UNKNOWN: None,
      handlers: None
    }
  }

  pub fn set_DESCRIBE(&mut self, DESCRIBE: ::models::DebugStatsUnknown) {
    self.DESCRIBE = Some(DESCRIBE);
  }

  pub fn with_DESCRIBE(mut self, DESCRIBE: ::models::DebugStatsUnknown) -> DebugStats {
    self.DESCRIBE = Some(DESCRIBE);
    self
  }

  pub fn DESCRIBE(&self) -> Option<&::models::DebugStatsUnknown> {
    self.DESCRIBE.as_ref()
  }

  pub fn reset_DESCRIBE(&mut self) {
    self.DESCRIBE = None;
  }

  pub fn set_UNKNOWN(&mut self, UNKNOWN: ::models::DebugStatsUnknown) {
    self.UNKNOWN = Some(UNKNOWN);
  }

  pub fn with_UNKNOWN(mut self, UNKNOWN: ::models::DebugStatsUnknown) -> DebugStats {
    self.UNKNOWN = Some(UNKNOWN);
    self
  }

  pub fn UNKNOWN(&self) -> Option<&::models::DebugStatsUnknown> {
    self.UNKNOWN.as_ref()
  }

  pub fn reset_UNKNOWN(&mut self) {
    self.UNKNOWN = None;
  }

  pub fn set_handlers(&mut self, handlers: Vec<::models::DebugStatsHandler>) {
    self.handlers = Some(handlers);
  }

  pub fn with_handlers(mut self, handlers: Vec<::models::DebugStatsHandler>) -> DebugStats {
    self.handlers = Some(handlers);
    self
  }

  pub fn handlers(&self) -> Option<&Vec<::models::DebugStatsHandler>> {
    self.handlers.as_ref()
  }

  pub fn reset_handlers(&mut self) {
    self.handlers = None;
  }

}



