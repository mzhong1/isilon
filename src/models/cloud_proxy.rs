/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

/// CloudProxy : The configuration settings for a network proxy

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudProxy {
  /// A host name or network address for connecting to this proxy
  #[serde(rename = "host")]
  host: Option<String>,
  /// A unique friendly name for this proxy configuration
  #[serde(rename = "name")]
  name: Option<String>,
  /// The password to connect to this proxy if required (write-only)
  #[serde(rename = "password")]
  password: Option<String>,
  /// The port used to connect to this proxy
  #[serde(rename = "port")]
  port: Option<i32>,
  /// The type of connection used to connect to this proxy
  #[serde(rename = "type")]
  _type: Option<String>,
  /// The username to connect to this proxy if required
  #[serde(rename = "username")]
  username: Option<String>
}

impl CloudProxy {
  /// The configuration settings for a network proxy
  pub fn new() -> CloudProxy {
    CloudProxy {
      host: None,
      name: None,
      password: None,
      port: None,
      _type: None,
      username: None
    }
  }

  pub fn set_host(&mut self, host: String) {
    self.host = Some(host);
  }

  pub fn with_host(mut self, host: String) -> CloudProxy {
    self.host = Some(host);
    self
  }

  pub fn host(&self) -> Option<&String> {
    self.host.as_ref()
  }

  pub fn reset_host(&mut self) {
    self.host = None;
  }

  pub fn set_name(&mut self, name: String) {
    self.name = Some(name);
  }

  pub fn with_name(mut self, name: String) -> CloudProxy {
    self.name = Some(name);
    self
  }

  pub fn name(&self) -> Option<&String> {
    self.name.as_ref()
  }

  pub fn reset_name(&mut self) {
    self.name = None;
  }

  pub fn set_password(&mut self, password: String) {
    self.password = Some(password);
  }

  pub fn with_password(mut self, password: String) -> CloudProxy {
    self.password = Some(password);
    self
  }

  pub fn password(&self) -> Option<&String> {
    self.password.as_ref()
  }

  pub fn reset_password(&mut self) {
    self.password = None;
  }

  pub fn set_port(&mut self, port: i32) {
    self.port = Some(port);
  }

  pub fn with_port(mut self, port: i32) -> CloudProxy {
    self.port = Some(port);
    self
  }

  pub fn port(&self) -> Option<&i32> {
    self.port.as_ref()
  }

  pub fn reset_port(&mut self) {
    self.port = None;
  }

  pub fn set_type(&mut self, _type: String) {
    self._type = Some(_type);
  }

  pub fn with_type(mut self, _type: String) -> CloudProxy {
    self._type = Some(_type);
    self
  }

  pub fn _type(&self) -> Option<&String> {
    self._type.as_ref()
  }

  pub fn reset_type(&mut self) {
    self._type = None;
  }

  pub fn set_username(&mut self, username: String) {
    self.username = Some(username);
  }

  pub fn with_username(mut self, username: String) -> CloudProxy {
    self.username = Some(username);
    self
  }

  pub fn username(&self) -> Option<&String> {
    self.username.as_ref()
  }

  pub fn reset_username(&mut self) {
    self.username = None;
  }

}



