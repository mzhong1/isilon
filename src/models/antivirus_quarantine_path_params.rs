/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// AntivirusQuarantinePathParams : The quarantine status of a file in /ifs.

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct AntivirusQuarantinePathParams {
  /// If true, this file is quarantined.  If false, the file is not quarantined.
  #[serde(rename = "quarantined")]
  quarantined: Option<bool>
}

impl AntivirusQuarantinePathParams {
  /// The quarantine status of a file in /ifs.
  pub fn new() -> AntivirusQuarantinePathParams {
    AntivirusQuarantinePathParams {
      quarantined: None
    }
  }

  pub fn set_quarantined(&mut self, quarantined: bool) {
    self.quarantined = Some(quarantined);
  }

  pub fn with_quarantined(mut self, quarantined: bool) -> AntivirusQuarantinePathParams {
    self.quarantined = Some(quarantined);
    self
  }

  pub fn quarantined(&self) -> Option<&bool> {
    self.quarantined.as_ref()
  }

  pub fn reset_quarantined(&mut self) {
    self.quarantined = None;
  }

}



