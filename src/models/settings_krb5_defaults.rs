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
pub struct SettingsKrb5Defaults {
  /// Specifies the properties for the global Kerberos authentication settings.
  #[serde(rename = "krb5_settings")]
  krb5_settings: Option<::models::SettingsKrb5DefaultsKrb5Settings>
}

impl SettingsKrb5Defaults {
  pub fn new() -> SettingsKrb5Defaults {
    SettingsKrb5Defaults {
      krb5_settings: None
    }
  }

  pub fn set_krb5_settings(&mut self, krb5_settings: ::models::SettingsKrb5DefaultsKrb5Settings) {
    self.krb5_settings = Some(krb5_settings);
  }

  pub fn with_krb5_settings(mut self, krb5_settings: ::models::SettingsKrb5DefaultsKrb5Settings) -> SettingsKrb5Defaults {
    self.krb5_settings = Some(krb5_settings);
    self
  }

  pub fn krb5_settings(&self) -> Option<&::models::SettingsKrb5DefaultsKrb5Settings> {
    self.krb5_settings.as_ref()
  }

  pub fn reset_krb5_settings(&mut self) {
    self.krb5_settings = None;
  }

}



