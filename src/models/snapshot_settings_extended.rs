

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotSettingsExtended {
  /// True if the scheduled snapshot creation services is on.
  #[serde(rename = "autocreate")]
  autocreate: Option<bool>,
  /// True if the scheduled snapshot deletion services is on.
  #[serde(rename = "autodelete")]
  autodelete: Option<bool>,
  /// Global switch for other accessible and visible settings.
  #[serde(rename = "global_visible_accessible")]
  global_visible_accessible: Option<bool>,
  /// True if root .snapshot directory is accessible locally.
  #[serde(rename = "local_root_accessible")]
  local_root_accessible: Option<bool>,
  /// True if root .snapshot directory is visible locally.
  #[serde(rename = "local_root_visible")]
  local_root_visible: Option<bool>,
  /// True if sub-directory .snapshot directory is accessible locally.
  #[serde(rename = "local_subdir_accessible")]
  local_subdir_accessible: Option<bool>,
  /// True if root .snapshot directory is accessible over NFS.
  #[serde(rename = "nfs_root_accessible")]
  nfs_root_accessible: Option<bool>,
  /// True if root .snapshot directory is visible over NFS.
  #[serde(rename = "nfs_root_visible")]
  nfs_root_visible: Option<bool>,
  /// True if sub-directory .snapshot directory is accessible over NFS.
  #[serde(rename = "nfs_subdir_accessible")]
  nfs_subdir_accessible: Option<bool>,
  /// Percentage of space to reserve for snapshots.
  #[serde(rename = "reserve")]
  reserve: Option<f32>,
  /// True if the system allows snapshot creation.
  #[serde(rename = "service")]
  service: Option<bool>,
  /// True if root .snapshot directory is accessible over SMB.
  #[serde(rename = "smb_root_accessible")]
  smb_root_accessible: Option<bool>,
  /// True if root .snapshot directory is visible over SMB.
  #[serde(rename = "smb_root_visible")]
  smb_root_visible: Option<bool>,
  /// True if sub-directory .snapshot directory is accessible over SMB.
  #[serde(rename = "smb_subdir_accessible")]
  smb_subdir_accessible: Option<bool>
}

