/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// CloudJobCreateParams : A cloud job for archiving or recalling files or restoring COI

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudJobCreateParams {
  /// The names of accounts for COI restore
  #[serde(rename = "accounts")]
  accounts: Option<Vec<String>>,
  /// Directories addressed by this job
  #[serde(rename = "directories")]
  directories: Option<Vec<String>>,
  /// The new expiration date in seconds
  #[serde(rename = "expiration_date")]
  expiration_date: Option<i32>,
  /// The file filtering logic to find files for this job. (Only applicable for 'recall' jobs)
  #[serde(rename = "file_matching_pattern")]
  file_matching_pattern: Option<::models::Empty>,
  /// Filenames addressed by this job
  #[serde(rename = "files")]
  files: Option<Vec<String>>,
  /// The name of an existing cloudpool policy to apply to this job. (Only applicable for 'archive' jobs)
  #[serde(rename = "policy")]
  policy: Option<String>,
  /// The type of cloud action to be performed by this job.
  #[serde(rename = "type")]
  _type: String
}

impl CloudJobCreateParams {
  /// A cloud job for archiving or recalling files or restoring COI
  pub fn new(_type: String) -> CloudJobCreateParams {
    CloudJobCreateParams {
      accounts: None,
      directories: None,
      expiration_date: None,
      file_matching_pattern: None,
      files: None,
      policy: None,
      _type: _type
    }
  }

  pub fn set_accounts(&mut self, accounts: Vec<String>) {
    self.accounts = Some(accounts);
  }

  pub fn with_accounts(mut self, accounts: Vec<String>) -> CloudJobCreateParams {
    self.accounts = Some(accounts);
    self
  }

  pub fn accounts(&self) -> Option<&Vec<String>> {
    self.accounts.as_ref()
  }

  pub fn reset_accounts(&mut self) {
    self.accounts = None;
  }

  pub fn set_directories(&mut self, directories: Vec<String>) {
    self.directories = Some(directories);
  }

  pub fn with_directories(mut self, directories: Vec<String>) -> CloudJobCreateParams {
    self.directories = Some(directories);
    self
  }

  pub fn directories(&self) -> Option<&Vec<String>> {
    self.directories.as_ref()
  }

  pub fn reset_directories(&mut self) {
    self.directories = None;
  }

  pub fn set_expiration_date(&mut self, expiration_date: i32) {
    self.expiration_date = Some(expiration_date);
  }

  pub fn with_expiration_date(mut self, expiration_date: i32) -> CloudJobCreateParams {
    self.expiration_date = Some(expiration_date);
    self
  }

  pub fn expiration_date(&self) -> Option<&i32> {
    self.expiration_date.as_ref()
  }

  pub fn reset_expiration_date(&mut self) {
    self.expiration_date = None;
  }

  pub fn set_file_matching_pattern(&mut self, file_matching_pattern: ::models::Empty) {
    self.file_matching_pattern = Some(file_matching_pattern);
  }

  pub fn with_file_matching_pattern(mut self, file_matching_pattern: ::models::Empty) -> CloudJobCreateParams {
    self.file_matching_pattern = Some(file_matching_pattern);
    self
  }

  pub fn file_matching_pattern(&self) -> Option<&::models::Empty> {
    self.file_matching_pattern.as_ref()
  }

  pub fn reset_file_matching_pattern(&mut self) {
    self.file_matching_pattern = None;
  }

  pub fn set_files(&mut self, files: Vec<String>) {
    self.files = Some(files);
  }

  pub fn with_files(mut self, files: Vec<String>) -> CloudJobCreateParams {
    self.files = Some(files);
    self
  }

  pub fn files(&self) -> Option<&Vec<String>> {
    self.files.as_ref()
  }

  pub fn reset_files(&mut self) {
    self.files = None;
  }

  pub fn set_policy(&mut self, policy: String) {
    self.policy = Some(policy);
  }

  pub fn with_policy(mut self, policy: String) -> CloudJobCreateParams {
    self.policy = Some(policy);
    self
  }

  pub fn policy(&self) -> Option<&String> {
    self.policy.as_ref()
  }

  pub fn reset_policy(&mut self) {
    self.policy = None;
  }

  pub fn set_type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with_type(mut self, _type: String) -> CloudJobCreateParams {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


}



