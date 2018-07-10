

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct AntivirusSettings {
  /// Antivirus settings.
  #[serde(rename = "settings")]
  settings: Option<::models::AntivirusSettingsSettings>
}

