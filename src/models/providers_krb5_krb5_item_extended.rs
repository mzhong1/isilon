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
pub struct ProvidersKrb5Krb5ItemExtended {
  /// Groupnet identifier.
  #[serde(rename = "groupnet")]
  groupnet: Option<String>,
  /// Specifies the Kerberos provider ID.
  #[serde(rename = "id")]
  id: Option<String>,
  /// Specifies the key information for the Kerberos SPNs.
  #[serde(rename = "keytab_entries")]
  keytab_entries: Option<Vec<::models::ProvidersKrb5IdParamsKeytabEntry>>,
  /// Specifies the path to a keytab file to import.
  #[serde(rename = "keytab_file")]
  keytab_file: Option<String>,
  /// If true, keys are managed manually. If false, keys are managed through kadmin.
  #[serde(rename = "manual_keying")]
  manual_keying: Option<bool>,
  /// Specifies the Kerberos provider name.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Specifies the name of realm.
  #[serde(rename = "realm")]
  realm: Option<String>,
  /// Specifies the recommended SPNs.
  #[serde(rename = "recommended_spns")]
  recommended_spns: Option<Vec<String>>,
  /// Specifies the status of the provider.
  #[serde(rename = "status")]
  status: Option<String>,
  /// If true, indicates that this provider instance was created by OneFS and cannot be removed
  #[serde(rename = "system")]
  system: Option<bool>,
  /// Specifies the name of the user that performs kadmin tasks.
  #[serde(rename = "user")]
  user: Option<String>,
  /// Specifies the Kerberos provider password.
  #[serde(rename = "password")]
  password: Option<String>
}

impl ProvidersKrb5Krb5ItemExtended {
  pub fn new() -> ProvidersKrb5Krb5ItemExtended {
    ProvidersKrb5Krb5ItemExtended {
      groupnet: None,
      id: None,
      keytab_entries: None,
      keytab_file: None,
      manual_keying: None,
      name: None,
      realm: None,
      recommended_spns: None,
      status: None,
      system: None,
      user: None,
      password: None
    }
  }

  pub fn set_groupnet(&mut self, groupnet: String) {
    self.groupnet = Some(groupnet);
  }

  pub fn with_groupnet(mut self, groupnet: String) -> ProvidersKrb5Krb5ItemExtended {
    self.groupnet = Some(groupnet);
    self
  }

  pub fn groupnet(&self) -> Option<&String> {
    self.groupnet.as_ref()
  }

  pub fn reset_groupnet(&mut self) {
    self.groupnet = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: String) -> ProvidersKrb5Krb5ItemExtended {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&String> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_keytab_entries(&mut self, keytab_entries: Vec<::models::ProvidersKrb5IdParamsKeytabEntry>) {
    self.keytab_entries = Some(keytab_entries);
  }

  pub fn with_keytab_entries(mut self, keytab_entries: Vec<::models::ProvidersKrb5IdParamsKeytabEntry>) -> ProvidersKrb5Krb5ItemExtended {
    self.keytab_entries = Some(keytab_entries);
    self
  }

  pub fn keytab_entries(&self) -> Option<&Vec<::models::ProvidersKrb5IdParamsKeytabEntry>> {
    self.keytab_entries.as_ref()
  }

  pub fn reset_keytab_entries(&mut self) {
    self.keytab_entries = None;
  }

  pub fn set_keytab_file(&mut self, keytab_file: String) {
    self.keytab_file = Some(keytab_file);
  }

  pub fn with_keytab_file(mut self, keytab_file: String) -> ProvidersKrb5Krb5ItemExtended {
    self.keytab_file = Some(keytab_file);
    self
  }

  pub fn keytab_file(&self) -> Option<&String> {
    self.keytab_file.as_ref()
  }

  pub fn reset_keytab_file(&mut self) {
    self.keytab_file = None;
  }

  pub fn set_manual_keying(&mut self, manual_keying: bool) {
    self.manual_keying = Some(manual_keying);
  }

  pub fn with_manual_keying(mut self, manual_keying: bool) -> ProvidersKrb5Krb5ItemExtended {
    self.manual_keying = Some(manual_keying);
    self
  }

  pub fn manual_keying(&self) -> Option<&bool> {
    self.manual_keying.as_ref()
  }

  pub fn reset_manual_keying(&mut self) {
    self.manual_keying = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> ProvidersKrb5Krb5ItemExtended {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_realm(&mut self, realm: String) {
    self.realm = Some(realm);
  }

  pub fn with_realm(mut self, realm: String) -> ProvidersKrb5Krb5ItemExtended {
    self.realm = Some(realm);
    self
  }

  pub fn realm(&self) -> Option<&String> {
    self.realm.as_ref()
  }

  pub fn reset_realm(&mut self) {
    self.realm = None;
  }

  pub fn set_recommended_spns(&mut self, recommended_spns: Vec<String>) {
    self.recommended_spns = Some(recommended_spns);
  }

  pub fn with_recommended_spns(mut self, recommended_spns: Vec<String>) -> ProvidersKrb5Krb5ItemExtended {
    self.recommended_spns = Some(recommended_spns);
    self
  }

  pub fn recommended_spns(&self) -> Option<&Vec<String>> {
    self.recommended_spns.as_ref()
  }

  pub fn reset_recommended_spns(&mut self) {
    self.recommended_spns = None;
  }

  pub fn set_status(&mut self, status: String) {
    self.status = Some(status);
  }

  pub fn with_status(mut self, status: String) -> ProvidersKrb5Krb5ItemExtended {
    self.status = Some(status);
    self
  }

  pub fn status(&self) -> Option<&String> {
    self.status.as_ref()
  }

  pub fn reset_status(&mut self) {
    self.status = None;
  }

  pub fn set_system(&mut self, system: bool) {
    self.system = Some(system);
  }

  pub fn with_system(mut self, system: bool) -> ProvidersKrb5Krb5ItemExtended {
    self.system = Some(system);
    self
  }

  pub fn system(&self) -> Option<&bool> {
    self.system.as_ref()
  }

  pub fn reset_system(&mut self) {
    self.system = None;
  }

  pub fn set_user(&mut self, user: String) {
    self.user = Some(user);
  }

  pub fn with_user(mut self, user: String) -> ProvidersKrb5Krb5ItemExtended {
    self.user = Some(user);
    self
  }

  pub fn user(&self) -> Option<&String> {
    self.user.as_ref()
  }

  pub fn reset_user(&mut self) {
    self.user = None;
  }

  pub fn set_password(&mut self, password: String) {
    self.password = Some(password);
  }

  pub fn with_password(mut self, password: String) -> ProvidersKrb5Krb5ItemExtended {
    self.password = Some(password);
    self
  }

  pub fn password(&self) -> Option<&String> {
    self.password.as_ref()
  }

  pub fn reset_password(&mut self) {
    self.password = None;
  }

}



