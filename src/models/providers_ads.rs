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
pub struct ProvidersAds {
  #[serde(rename = "ads")]
  ads: Option<Vec<::models::ProvidersAdsAdsItem>>
}

impl ProvidersAds {
  pub fn new() -> ProvidersAds {
    ProvidersAds {
      ads: None
    }
  }

  pub fn set_ads(&mut self, ads: Vec<::models::ProvidersAdsAdsItem>) {
    self.ads = Some(ads);
  }

  pub fn with_ads(mut self, ads: Vec<::models::ProvidersAdsAdsItem>) -> ProvidersAds {
    self.ads = Some(ads);
    self
  }

  pub fn ads(&self) -> Option<&Vec<::models::ProvidersAdsAdsItem>> {
    self.ads.as_ref()
  }

  pub fn reset_ads(&mut self) {
    self.ads = None;
  }

}



