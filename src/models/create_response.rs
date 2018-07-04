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
pub struct CreateResponse {
  /// ID of created item that can be used to refer to item in the collection-item resource path.
  #[serde(rename = "id")]
  id: String
}

impl CreateResponse {
  pub fn new(id: String) -> CreateResponse {
    CreateResponse {
      id: id
    }
  }

  pub fn set_id(&mut self, id: String) {
    self.id = id;
  }

  pub fn with_id(mut self, id: String) -> CreateResponse {
    self.id = id;
    self
  }

  pub fn id(&self) -> &String {
    &self.id
  }


}



