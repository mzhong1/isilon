

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvidersAdsAdsItemExtended {
  /// Allocates an ID for an unmapped Active Directory (ADS) group. ADS groups without GIDs can be proactively assigned a GID by the ID mapper. If the ID mapper option is disabled, GIDs are not proactively assigned, and when a primary group for a user does not include a GID, the system may allocate one. 
  #[serde(rename = "allocate_gids")]
  allocate_gids: Option<bool>,
  /// Allocates a user ID for an unmapped Active Directory (ADS) user. ADS users without UIDs can be proactively assigned a UID by the ID mapper. IF the ID mapper option is disabled, UIDs are not proactively assigned, and when an identify for a user does not include a UID, the system may allocate one.
  #[serde(rename = "allocate_uids")]
  allocate_uids: Option<bool>,
  /// Enables lookup of unqualified user names in the primary domain.
  #[serde(rename = "assume_default_domain")]
  assume_default_domain: Option<bool>,
  /// Enables authentication and identity management through the authentication provider.
  #[serde(rename = "authentication")]
  authentication: Option<bool>,
  /// Specifies the time in seconds between provider online checks.
  #[serde(rename = "check_online_interval")]
  check_online_interval: Option<i32>,
  /// Specifies the current time for the domain controllers.
  #[serde(rename = "controller_time")]
  controller_time: Option<i32>,
  /// Automatically creates a home directory on the first login.
  #[serde(rename = "create_home_directory")]
  create_home_directory: Option<bool>,
  /// Sends an alert if the domain goes offline.
  #[serde(rename = "domain_offline_alerts")]
  domain_offline_alerts: Option<bool>,
  /// Sets list of groups that can be resolved.
  #[serde(rename = "findable_groups")]
  findable_groups: Option<Vec<String>>,
  /// Sets list of users that can be resolved.
  #[serde(rename = "findable_users")]
  findable_users: Option<Vec<String>>,
  /// Specifies the Active Directory forest.
  #[serde(rename = "forest")]
  forest: Option<String>,
  /// Groupnet identifier.
  #[serde(rename = "groupnet")]
  groupnet: Option<String>,
  /// Specifies the path to the home directory template.
  #[serde(rename = "home_directory_template")]
  home_directory_template: Option<String>,
  /// Specifies the fully qualified hostname stored in the machine account.
  #[serde(rename = "hostname")]
  hostname: Option<String>,
  /// Specifies the ID of the Active Directory provider instance.
  #[serde(rename = "id")]
  id: Option<String>,
  /// If set to true, ignores all trusted domains.
  #[serde(rename = "ignore_all_trusts")]
  ignore_all_trusts: Option<bool>,
  /// Includes trusted domains when 'ignore_all_trusts' is set to false.
  #[serde(rename = "ignored_trusted_domains")]
  ignored_trusted_domains: Option<Vec<String>>,
  /// Includes trusted domains when 'ignore_all_trusts' is set to true.
  #[serde(rename = "include_trusted_domains")]
  include_trusted_domains: Option<Vec<String>>,
  /// Specifies Active Directory provider instance.
  #[serde(rename = "instance")]
  instance: Option<String>,
  /// Enables encryption and signing on LDAP requests.
  #[serde(rename = "ldap_sign_and_seal")]
  ldap_sign_and_seal: Option<bool>,
  /// Specifies the login shell path.
  #[serde(rename = "login_shell")]
  login_shell: Option<String>,
  /// Limits user and group lookups to the specified domains.
  #[serde(rename = "lookup_domains")]
  lookup_domains: Option<Vec<String>>,
  /// Looks up AD groups in other providers before allocating a group ID.
  #[serde(rename = "lookup_groups")]
  lookup_groups: Option<bool>,
  /// Normalizes AD group names to lowercase before look up.
  #[serde(rename = "lookup_normalize_groups")]
  lookup_normalize_groups: Option<bool>,
  /// Normalize AD user names to lowercase before look up.
  #[serde(rename = "lookup_normalize_users")]
  lookup_normalize_users: Option<bool>,
  /// Looks up AD users in other providers before allocating a user ID.
  #[serde(rename = "lookup_users")]
  lookup_users: Option<bool>,
  /// Specifies the SAM account name of the machine account.
  #[serde(rename = "machine_account")]
  machine_account: Option<String>,
  /// Specifies name to join AD as.
  #[serde(rename = "machine_name")]
  machine_name: Option<String>,
  /// Enables periodic changes of the machine password for security.
  #[serde(rename = "machine_password_changes")]
  machine_password_changes: Option<bool>,
  /// Sets maximum age of a password in seconds.
  #[serde(rename = "machine_password_lifespan")]
  machine_password_lifespan: Option<i32>,
  /// Specifies the Active Directory provider name.
  #[serde(rename = "name")]
  name: Option<String>,
  /// Specifies the NetBIOS domain name associated with the machine account.
  #[serde(rename = "netbios_domain")]
  netbios_domain: Option<String>,
  /// Specifies the domain controller for which the node has affinity.
  #[serde(rename = "node_dc_affinity")]
  node_dc_affinity: Option<String>,
  /// Specifies the timeout for the domain controller for which the local node has affinity.
  #[serde(rename = "node_dc_affinity_timeout")]
  node_dc_affinity_timeout: Option<i32>,
  /// Enables the Active Directory provider to respond to 'getpwent' and 'getgrent' requests.
  #[serde(rename = "nss_enumeration")]
  nss_enumeration: Option<bool>,
  /// Specifies the AD domain to which the provider is joined.
  #[serde(rename = "primary_domain")]
  primary_domain: Option<String>,
  /// Check the provider for filtered lists of findable and unfindable users and groups.
  #[serde(rename = "restrict_findable")]
  restrict_findable: Option<bool>,
  /// Specifies whether to support RFC 2307 attributes on ADS domain controllers.
  #[serde(rename = "sfu_support")]
  sfu_support: Option<String>,
  /// Specifies the site for the Active Directory.
  #[serde(rename = "site")]
  site: Option<String>,
  /// Specifies the status of the provider.
  #[serde(rename = "status")]
  status: Option<String>,
  /// Stores SFU mappings permanently in the ID mapper.
  #[serde(rename = "store_sfu_mappings")]
  store_sfu_mappings: Option<bool>,
  /// If set to true, indicates that this provider instance was created by OneFS and cannot be removed.
  #[serde(rename = "system")]
  system: Option<bool>,
  /// Specifies groups that cannot be resolved by the provider.
  #[serde(rename = "unfindable_groups")]
  unfindable_groups: Option<Vec<String>>,
  /// Specifies users that cannot be resolved by the provider.
  #[serde(rename = "unfindable_users")]
  unfindable_users: Option<Vec<String>>
}

