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
pub struct CreateSnapshotAliasResponse {
  /// The ID of the newly created snapshot alias.
  #[serde(rename = "id")]
  id: i32
}

impl CreateSnapshotAliasResponse {
  pub fn new(id: i32) -> CreateSnapshotAliasResponse {
    CreateSnapshotAliasResponse {
      id: id
    }
  }

  pub fn set_id(&mut self, id: i32) {
    self.id = id;
  }

  pub fn with_id(mut self, id: i32) -> CreateSnapshotAliasResponse {
    self.id = id;
    self
  }

  pub fn id(&self) -> &i32 {
    &self.id
  }


}



