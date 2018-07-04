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
pub struct MappingUsersLookupMappingItemGroup {
  #[serde(rename = "dn")]
  dn: Option<String>,
  #[serde(rename = "dns_domain")]
  dns_domain: Option<String>,
  #[serde(rename = "domain")]
  domain: Option<String>,
  #[serde(rename = "email")]
  email: Option<String>,
  /// If true, the authenticated user is enabled.
  #[serde(rename = "enabled")]
  enabled: Option<bool>,
  /// If true, the authenticated auth user is expired.
  #[serde(rename = "expired")]
  expired: Option<bool>,
  #[serde(rename = "expiry")]
  expiry: Option<i32>,
  #[serde(rename = "gecos")]
  gecos: Option<String>,
  /// If true, indicates that the GID was generated.
  #[serde(rename = "generated_gid")]
  generated_gid: Option<bool>,
  /// If true, indicates that the UID was generated.
  #[serde(rename = "generated_uid")]
  generated_uid: Option<bool>,
  /// If true, indicates that the UPN was generated.
  #[serde(rename = "generated_upn")]
  generated_upn: Option<bool>,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "gid")]
  gid: Option<::models::AuthAccessAccessItemFileGroup>,
  #[serde(rename = "home_directory")]
  home_directory: Option<String>,
  /// Specifies the user or group ID.
  #[serde(rename = "id")]
  id: String,
  /// If true, the account is locked out.
  #[serde(rename = "locked")]
  locked: Option<bool>,
  /// Specifies the maximum time in seconds allowed before the password expires.
  #[serde(rename = "max_password_age")]
  max_password_age: Option<i32>,
  #[serde(rename = "member_of")]
  member_of: Option<Vec<::models::AuthAccessAccessItemFileGroup>>,
  /// Specifies a user or group name.
  #[serde(rename = "name")]
  name: String,
  #[serde(rename = "object_history")]
  object_history: Option<Vec<::models::AuthGroupObjectHistoryItem>>,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "on_disk_group_identity")]
  on_disk_group_identity: Option<::models::AuthAccessAccessItemFileGroup>,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "on_disk_user_identity")]
  on_disk_user_identity: Option<::models::AuthAccessAccessItemFileGroup>,
  /// If true, the password has expired.
  #[serde(rename = "password_expired")]
  password_expired: Option<bool>,
  /// If true, the password is allowed to expire.
  #[serde(rename = "password_expires")]
  password_expires: Option<bool>,
  #[serde(rename = "password_expiry")]
  password_expiry: Option<i32>,
  #[serde(rename = "password_last_set")]
  password_last_set: Option<i32>,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "primary_group_sid")]
  primary_group_sid: Option<::models::AuthAccessAccessItemFileGroup>,
  /// If true, prompts the user to change their password on next login.
  #[serde(rename = "prompt_password_change")]
  prompt_password_change: Option<bool>,
  #[serde(rename = "provider")]
  provider: Option<String>,
  #[serde(rename = "sam_account_name")]
  sam_account_name: Option<String>,
  #[serde(rename = "shell")]
  shell: Option<String>,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "sid")]
  sid: Option<::models::AuthAccessAccessItemFileGroup>,
  /// Specifies the object type.
  #[serde(rename = "type")]
  _type: String,
  /// Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.
  #[serde(rename = "uid")]
  uid: Option<::models::AuthAccessAccessItemFileGroup>,
  #[serde(rename = "upn")]
  upn: Option<String>,
  /// If true, the user password can be changed.
  #[serde(rename = "user_can_change_password")]
  user_can_change_password: Option<bool>
}

impl MappingUsersLookupMappingItemGroup {
  pub fn new(id: String, name: String, _type: String) -> MappingUsersLookupMappingItemGroup {
    MappingUsersLookupMappingItemGroup {
      dn: None,
      dns_domain: None,
      domain: None,
      email: None,
      enabled: None,
      expired: None,
      expiry: None,
      gecos: None,
      generated_gid: None,
      generated_uid: None,
      generated_upn: None,
      gid: None,
      home_directory: None,
      id: id,
      locked: None,
      max_password_age: None,
      member_of: None,
      name: name,
      object_history: None,
      on_disk_group_identity: None,
      on_disk_user_identity: None,
      password_expired: None,
      password_expires: None,
      password_expiry: None,
      password_last_set: None,
      primary_group_sid: None,
      prompt_password_change: None,
      provider: None,
      sam_account_name: None,
      shell: None,
      sid: None,
      _type: _type,
      uid: None,
      upn: None,
      user_can_change_password: None
    }
  }

  pub fn set_dn(&mut self, dn: String) {
    self.dn = Some(dn);
  }

  pub fn with_dn(mut self, dn: String) -> MappingUsersLookupMappingItemGroup {
    self.dn = Some(dn);
    self
  }

  pub fn dn(&self) -> Option<&String> {
    self.dn.as_ref()
  }

  pub fn reset_dn(&mut self) {
    self.dn = None;
  }

  pub fn set_dns_domain(&mut self, dns_domain: String) {
    self.dns_domain = Some(dns_domain);
  }

  pub fn with_dns_domain(mut self, dns_domain: String) -> MappingUsersLookupMappingItemGroup {
    self.dns_domain = Some(dns_domain);
    self
  }

  pub fn dns_domain(&self) -> Option<&String> {
    self.dns_domain.as_ref()
  }

  pub fn reset_dns_domain(&mut self) {
    self.dns_domain = None;
  }

  pub fn set_domain(&mut self, domain: String) {
    self.domain = Some(domain);
  }

  pub fn with_domain(mut self, domain: String) -> MappingUsersLookupMappingItemGroup {
    self.domain = Some(domain);
    self
  }

  pub fn domain(&self) -> Option<&String> {
    self.domain.as_ref()
  }

  pub fn reset_domain(&mut self) {
    self.domain = None;
  }

  pub fn set_email(&mut self, email: String) {
    self.email = Some(email);
  }

  pub fn with_email(mut self, email: String) -> MappingUsersLookupMappingItemGroup {
    self.email = Some(email);
    self
  }

  pub fn email(&self) -> Option<&String> {
    self.email.as_ref()
  }

  pub fn reset_email(&mut self) {
    self.email = None;
  }

  pub fn set_enabled(&mut self, enabled: bool) {
    self.enabled = Some(enabled);
  }

  pub fn with_enabled(mut self, enabled: bool) -> MappingUsersLookupMappingItemGroup {
    self.enabled = Some(enabled);
    self
  }

  pub fn enabled(&self) -> Option<&bool> {
    self.enabled.as_ref()
  }

  pub fn reset_enabled(&mut self) {
    self.enabled = None;
  }

  pub fn set_expired(&mut self, expired: bool) {
    self.expired = Some(expired);
  }

  pub fn with_expired(mut self, expired: bool) -> MappingUsersLookupMappingItemGroup {
    self.expired = Some(expired);
    self
  }

  pub fn expired(&self) -> Option<&bool> {
    self.expired.as_ref()
  }

  pub fn reset_expired(&mut self) {
    self.expired = None;
  }

  pub fn set_expiry(&mut self, expiry: i32) {
    self.expiry = Some(expiry);
  }

  pub fn with_expiry(mut self, expiry: i32) -> MappingUsersLookupMappingItemGroup {
    self.expiry = Some(expiry);
    self
  }

  pub fn expiry(&self) -> Option<&i32> {
    self.expiry.as_ref()
  }

  pub fn reset_expiry(&mut self) {
    self.expiry = None;
  }

  pub fn set_gecos(&mut self, gecos: String) {
    self.gecos = Some(gecos);
  }

  pub fn with_gecos(mut self, gecos: String) -> MappingUsersLookupMappingItemGroup {
    self.gecos = Some(gecos);
    self
  }

  pub fn gecos(&self) -> Option<&String> {
    self.gecos.as_ref()
  }

  pub fn reset_gecos(&mut self) {
    self.gecos = None;
  }

  pub fn set_generated_gid(&mut self, generated_gid: bool) {
    self.generated_gid = Some(generated_gid);
  }

  pub fn with_generated_gid(mut self, generated_gid: bool) -> MappingUsersLookupMappingItemGroup {
    self.generated_gid = Some(generated_gid);
    self
  }

  pub fn generated_gid(&self) -> Option<&bool> {
    self.generated_gid.as_ref()
  }

  pub fn reset_generated_gid(&mut self) {
    self.generated_gid = None;
  }

  pub fn set_generated_uid(&mut self, generated_uid: bool) {
    self.generated_uid = Some(generated_uid);
  }

  pub fn with_generated_uid(mut self, generated_uid: bool) -> MappingUsersLookupMappingItemGroup {
    self.generated_uid = Some(generated_uid);
    self
  }

  pub fn generated_uid(&self) -> Option<&bool> {
    self.generated_uid.as_ref()
  }

  pub fn reset_generated_uid(&mut self) {
    self.generated_uid = None;
  }

  pub fn set_generated_upn(&mut self, generated_upn: bool) {
    self.generated_upn = Some(generated_upn);
  }

  pub fn with_generated_upn(mut self, generated_upn: bool) -> MappingUsersLookupMappingItemGroup {
    self.generated_upn = Some(generated_upn);
    self
  }

  pub fn generated_upn(&self) -> Option<&bool> {
    self.generated_upn.as_ref()
  }

  pub fn reset_generated_upn(&mut self) {
    self.generated_upn = None;
  }

  pub fn set_gid(&mut self, gid: ::models::AuthAccessAccessItemFileGroup) {
    self.gid = Some(gid);
  }

  pub fn with_gid(mut self, gid: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.gid = Some(gid);
    self
  }

  pub fn gid(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.gid.as_ref()
  }

  pub fn reset_gid(&mut self) {
    self.gid = None;
  }

  pub fn set_home_directory(&mut self, home_directory: String) {
    self.home_directory = Some(home_directory);
  }

  pub fn with_home_directory(mut self, home_directory: String) -> MappingUsersLookupMappingItemGroup {
    self.home_directory = Some(home_directory);
    self
  }

  pub fn home_directory(&self) -> Option<&String> {
    self.home_directory.as_ref()
  }

  pub fn reset_home_directory(&mut self) {
    self.home_directory = None;
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> MappingUsersLookupMappingItemGroup {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


  pub fn set_locked(&mut self, locked: bool) {
    self.locked = Some(locked);
  }

  pub fn with_locked(mut self, locked: bool) -> MappingUsersLookupMappingItemGroup {
    self.locked = Some(locked);
    self
  }

  pub fn locked(&self) -> Option<&bool> {
    self.locked.as_ref()
  }

  pub fn reset_locked(&mut self) {
    self.locked = None;
  }

  pub fn set_max_password_age(&mut self, max_password_age: i32) {
    self.max_password_age = Some(max_password_age);
  }

  pub fn with_max_password_age(mut self, max_password_age: i32) -> MappingUsersLookupMappingItemGroup {
    self.max_password_age = Some(max_password_age);
    self
  }

  pub fn max_password_age(&self) -> Option<&i32> {
    self.max_password_age.as_ref()
  }

  pub fn reset_max_password_age(&mut self) {
    self.max_password_age = None;
  }

  pub fn set_member_of(&mut self, member_of: Vec<::models::AuthAccessAccessItemFileGroup>) {
    self.member_of = Some(member_of);
  }

  pub fn with_member_of(mut self, member_of: Vec<::models::AuthAccessAccessItemFileGroup>) -> MappingUsersLookupMappingItemGroup {
    self.member_of = Some(member_of);
    self
  }

  pub fn member_of(&self) -> Option<&Vec<::models::AuthAccessAccessItemFileGroup>> {
    self.member_of.as_ref()
  }

  pub fn reset_member_of(&mut self) {
    self.member_of = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = name;
  }

  pub fn with_name(mut self, name: String) -> MappingUsersLookupMappingItemGroup {
    self.name = name;
    self
  }

  pub fn name(&self) -> &String {
    &self.name
  }


  pub fn set_object_history(&mut self, object_history: Vec<::models::AuthGroupObjectHistoryItem>) {
    self.object_history = Some(object_history);
  }

  pub fn with_object_history(mut self, object_history: Vec<::models::AuthGroupObjectHistoryItem>) -> MappingUsersLookupMappingItemGroup {
    self.object_history = Some(object_history);
    self
  }

  pub fn object_history(&self) -> Option<&Vec<::models::AuthGroupObjectHistoryItem>> {
    self.object_history.as_ref()
  }

  pub fn reset_object_history(&mut self) {
    self.object_history = None;
  }

  pub fn set_on_disk_group_identity(&mut self, on_disk_group_identity: ::models::AuthAccessAccessItemFileGroup) {
    self.on_disk_group_identity = Some(on_disk_group_identity);
  }

  pub fn with_on_disk_group_identity(mut self, on_disk_group_identity: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.on_disk_group_identity = Some(on_disk_group_identity);
    self
  }

  pub fn on_disk_group_identity(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.on_disk_group_identity.as_ref()
  }

  pub fn reset_on_disk_group_identity(&mut self) {
    self.on_disk_group_identity = None;
  }

  pub fn set_on_disk_user_identity(&mut self, on_disk_user_identity: ::models::AuthAccessAccessItemFileGroup) {
    self.on_disk_user_identity = Some(on_disk_user_identity);
  }

  pub fn with_on_disk_user_identity(mut self, on_disk_user_identity: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.on_disk_user_identity = Some(on_disk_user_identity);
    self
  }

  pub fn on_disk_user_identity(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.on_disk_user_identity.as_ref()
  }

  pub fn reset_on_disk_user_identity(&mut self) {
    self.on_disk_user_identity = None;
  }

  pub fn set_password_expired(&mut self, password_expired: bool) {
    self.password_expired = Some(password_expired);
  }

  pub fn with_password_expired(mut self, password_expired: bool) -> MappingUsersLookupMappingItemGroup {
    self.password_expired = Some(password_expired);
    self
  }

  pub fn password_expired(&self) -> Option<&bool> {
    self.password_expired.as_ref()
  }

  pub fn reset_password_expired(&mut self) {
    self.password_expired = None;
  }

  pub fn set_password_expires(&mut self, password_expires: bool) {
    self.password_expires = Some(password_expires);
  }

  pub fn with_password_expires(mut self, password_expires: bool) -> MappingUsersLookupMappingItemGroup {
    self.password_expires = Some(password_expires);
    self
  }

  pub fn password_expires(&self) -> Option<&bool> {
    self.password_expires.as_ref()
  }

  pub fn reset_password_expires(&mut self) {
    self.password_expires = None;
  }

  pub fn set_password_expiry(&mut self, password_expiry: i32) {
    self.password_expiry = Some(password_expiry);
  }

  pub fn with_password_expiry(mut self, password_expiry: i32) -> MappingUsersLookupMappingItemGroup {
    self.password_expiry = Some(password_expiry);
    self
  }

  pub fn password_expiry(&self) -> Option<&i32> {
    self.password_expiry.as_ref()
  }

  pub fn reset_password_expiry(&mut self) {
    self.password_expiry = None;
  }

  pub fn set_password_last_set(&mut self, password_last_set: i32) {
    self.password_last_set = Some(password_last_set);
  }

  pub fn with_password_last_set(mut self, password_last_set: i32) -> MappingUsersLookupMappingItemGroup {
    self.password_last_set = Some(password_last_set);
    self
  }

  pub fn password_last_set(&self) -> Option<&i32> {
    self.password_last_set.as_ref()
  }

  pub fn reset_password_last_set(&mut self) {
    self.password_last_set = None;
  }

  pub fn set_primary_group_sid(&mut self, primary_group_sid: ::models::AuthAccessAccessItemFileGroup) {
    self.primary_group_sid = Some(primary_group_sid);
  }

  pub fn with_primary_group_sid(mut self, primary_group_sid: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.primary_group_sid = Some(primary_group_sid);
    self
  }

  pub fn primary_group_sid(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.primary_group_sid.as_ref()
  }

  pub fn reset_primary_group_sid(&mut self) {
    self.primary_group_sid = None;
  }

  pub fn set_prompt_password_change(&mut self, prompt_password_change: bool) {
    self.prompt_password_change = Some(prompt_password_change);
  }

  pub fn with_prompt_password_change(mut self, prompt_password_change: bool) -> MappingUsersLookupMappingItemGroup {
    self.prompt_password_change = Some(prompt_password_change);
    self
  }

  pub fn prompt_password_change(&self) -> Option<&bool> {
    self.prompt_password_change.as_ref()
  }

  pub fn reset_prompt_password_change(&mut self) {
    self.prompt_password_change = None;
  }

  pub fn set_provider(&mut self, provider: String) {
    self.provider = Some(provider);
  }

  pub fn with_provider(mut self, provider: String) -> MappingUsersLookupMappingItemGroup {
    self.provider = Some(provider);
    self
  }

  pub fn provider(&self) -> Option<&String> {
    self.provider.as_ref()
  }

  pub fn reset_provider(&mut self) {
    self.provider = None;
  }

  pub fn set_sam_account_name(&mut self, sam_account_name: String) {
    self.sam_account_name = Some(sam_account_name);
  }

  pub fn with_sam_account_name(mut self, sam_account_name: String) -> MappingUsersLookupMappingItemGroup {
    self.sam_account_name = Some(sam_account_name);
    self
  }

  pub fn sam_account_name(&self) -> Option<&String> {
    self.sam_account_name.as_ref()
  }

  pub fn reset_sam_account_name(&mut self) {
    self.sam_account_name = None;
  }

  pub fn set_shell(&mut self, shell: String) {
    self.shell = Some(shell);
  }

  pub fn with_shell(mut self, shell: String) -> MappingUsersLookupMappingItemGroup {
    self.shell = Some(shell);
    self
  }

  pub fn shell(&self) -> Option<&String> {
    self.shell.as_ref()
  }

  pub fn reset_shell(&mut self) {
    self.shell = None;
  }

  pub fn set_sid(&mut self, sid: ::models::AuthAccessAccessItemFileGroup) {
    self.sid = Some(sid);
  }

  pub fn with_sid(mut self, sid: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.sid = Some(sid);
    self
  }

  pub fn sid(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.sid.as_ref()
  }

  pub fn reset_sid(&mut self) {
    self.sid = None;
  }

  pub fn set_type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with_type(mut self, _type: String) -> MappingUsersLookupMappingItemGroup {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


  pub fn set_uid(&mut self, uid: ::models::AuthAccessAccessItemFileGroup) {
    self.uid = Some(uid);
  }

  pub fn with_uid(mut self, uid: ::models::AuthAccessAccessItemFileGroup) -> MappingUsersLookupMappingItemGroup {
    self.uid = Some(uid);
    self
  }

  pub fn uid(&self) -> Option<&::models::AuthAccessAccessItemFileGroup> {
    self.uid.as_ref()
  }

  pub fn reset_uid(&mut self) {
    self.uid = None;
  }

  pub fn set_upn(&mut self, upn: String) {
    self.upn = Some(upn);
  }

  pub fn with_upn(mut self, upn: String) -> MappingUsersLookupMappingItemGroup {
    self.upn = Some(upn);
    self
  }

  pub fn upn(&self) -> Option<&String> {
    self.upn.as_ref()
  }

  pub fn reset_upn(&mut self) {
    self.upn = None;
  }

  pub fn set_user_can_change_password(&mut self, user_can_change_password: bool) {
    self.user_can_change_password = Some(user_can_change_password);
  }

  pub fn with_user_can_change_password(mut self, user_can_change_password: bool) -> MappingUsersLookupMappingItemGroup {
    self.user_can_change_password = Some(user_can_change_password);
    self
  }

  pub fn user_can_change_password(&self) -> Option<&bool> {
    self.user_can_change_password.as_ref()
  }

  pub fn reset_user_can_change_password(&mut self) {
    self.user_can_change_password = None;
  }

}



