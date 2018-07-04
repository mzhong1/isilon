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
pub struct NetworkDnscacheSettings {
  /// DNS cache entry limit
  #[serde(rename = "cache_entry_limit")]
  cache_entry_limit: i32,
  /// Timeout value for calls made to other nodes in the cluster
  #[serde(rename = "cluster_timeout")]
  cluster_timeout: i32,
  /// Timeout value for calls made to the dns resolvers
  #[serde(rename = "dns_timeout")]
  dns_timeout: i32,
  /// Lead time to refresh cache entries nearing expiration
  #[serde(rename = "eager_refresh")]
  eager_refresh: i32,
  /// Deltas for checking cbind cluster health
  #[serde(rename = "testping_delta")]
  testping_delta: i32,
  /// Upper bound on ttl for cache hits
  #[serde(rename = "ttl_max_noerror")]
  ttl_max_noerror: i32,
  /// Upper bound on ttl for nxdomain
  #[serde(rename = "ttl_max_nxdomain")]
  ttl_max_nxdomain: i32,
  /// Upper bound on ttl for non-nxdomain failures
  #[serde(rename = "ttl_max_other")]
  ttl_max_other: i32,
  /// Upper bound on ttl for server failures
  #[serde(rename = "ttl_max_servfail")]
  ttl_max_servfail: i32,
  /// Lower bound on ttl for cache hits
  #[serde(rename = "ttl_min_noerror")]
  ttl_min_noerror: i32,
  /// Lower bound on ttl for nxdomain
  #[serde(rename = "ttl_min_nxdomain")]
  ttl_min_nxdomain: i32,
  /// Lower bound on ttl for non-nxdomain failures
  #[serde(rename = "ttl_min_other")]
  ttl_min_other: i32,
  /// Lower bound on ttl for server failures
  #[serde(rename = "ttl_min_servfail")]
  ttl_min_servfail: i32
}

impl NetworkDnscacheSettings {
  pub fn new(cache_entry_limit: i32, cluster_timeout: i32, dns_timeout: i32, eager_refresh: i32, testping_delta: i32, ttl_max_noerror: i32, ttl_max_nxdomain: i32, ttl_max_other: i32, ttl_max_servfail: i32, ttl_min_noerror: i32, ttl_min_nxdomain: i32, ttl_min_other: i32, ttl_min_servfail: i32) -> NetworkDnscacheSettings {
    NetworkDnscacheSettings {
      cache_entry_limit: cache_entry_limit,
      cluster_timeout: cluster_timeout,
      dns_timeout: dns_timeout,
      eager_refresh: eager_refresh,
      testping_delta: testping_delta,
      ttl_max_noerror: ttl_max_noerror,
      ttl_max_nxdomain: ttl_max_nxdomain,
      ttl_max_other: ttl_max_other,
      ttl_max_servfail: ttl_max_servfail,
      ttl_min_noerror: ttl_min_noerror,
      ttl_min_nxdomain: ttl_min_nxdomain,
      ttl_min_other: ttl_min_other,
      ttl_min_servfail: ttl_min_servfail
    }
  }

  pub fn set_cache_entry_limit(&mut self, cache_entry_limit: i32) {
    self.cache_entry_limit = cache_entry_limit;
  }

  pub fn with_cache_entry_limit(mut self, cache_entry_limit: i32) -> NetworkDnscacheSettings {
    self.cache_entry_limit = cache_entry_limit;
    self
  }

  pub fn cache_entry_limit(&self) -> &i32 {
    &self.cache_entry_limit
  }


  pub fn set_cluster_timeout(&mut self, cluster_timeout: i32) {
    self.cluster_timeout = cluster_timeout;
  }

  pub fn with_cluster_timeout(mut self, cluster_timeout: i32) -> NetworkDnscacheSettings {
    self.cluster_timeout = cluster_timeout;
    self
  }

  pub fn cluster_timeout(&self) -> &i32 {
    &self.cluster_timeout
  }


  pub fn set_dns_timeout(&mut self, dns_timeout: i32) {
    self.dns_timeout = dns_timeout;
  }

  pub fn with_dns_timeout(mut self, dns_timeout: i32) -> NetworkDnscacheSettings {
    self.dns_timeout = dns_timeout;
    self
  }

  pub fn dns_timeout(&self) -> &i32 {
    &self.dns_timeout
  }


  pub fn set_eager_refresh(&mut self, eager_refresh: i32) {
    self.eager_refresh = eager_refresh;
  }

  pub fn with_eager_refresh(mut self, eager_refresh: i32) -> NetworkDnscacheSettings {
    self.eager_refresh = eager_refresh;
    self
  }

  pub fn eager_refresh(&self) -> &i32 {
    &self.eager_refresh
  }


  pub fn set_testping_delta(&mut self, testping_delta: i32) {
    self.testping_delta = testping_delta;
  }

  pub fn with_testping_delta(mut self, testping_delta: i32) -> NetworkDnscacheSettings {
    self.testping_delta = testping_delta;
    self
  }

  pub fn testping_delta(&self) -> &i32 {
    &self.testping_delta
  }


  pub fn set_ttl_max_noerror(&mut self, ttl_max_noerror: i32) {
    self.ttl_max_noerror = ttl_max_noerror;
  }

  pub fn with_ttl_max_noerror(mut self, ttl_max_noerror: i32) -> NetworkDnscacheSettings {
    self.ttl_max_noerror = ttl_max_noerror;
    self
  }

  pub fn ttl_max_noerror(&self) -> &i32 {
    &self.ttl_max_noerror
  }


  pub fn set_ttl_max_nxdomain(&mut self, ttl_max_nxdomain: i32) {
    self.ttl_max_nxdomain = ttl_max_nxdomain;
  }

  pub fn with_ttl_max_nxdomain(mut self, ttl_max_nxdomain: i32) -> NetworkDnscacheSettings {
    self.ttl_max_nxdomain = ttl_max_nxdomain;
    self
  }

  pub fn ttl_max_nxdomain(&self) -> &i32 {
    &self.ttl_max_nxdomain
  }


  pub fn set_ttl_max_other(&mut self, ttl_max_other: i32) {
    self.ttl_max_other = ttl_max_other;
  }

  pub fn with_ttl_max_other(mut self, ttl_max_other: i32) -> NetworkDnscacheSettings {
    self.ttl_max_other = ttl_max_other;
    self
  }

  pub fn ttl_max_other(&self) -> &i32 {
    &self.ttl_max_other
  }


  pub fn set_ttl_max_servfail(&mut self, ttl_max_servfail: i32) {
    self.ttl_max_servfail = ttl_max_servfail;
  }

  pub fn with_ttl_max_servfail(mut self, ttl_max_servfail: i32) -> NetworkDnscacheSettings {
    self.ttl_max_servfail = ttl_max_servfail;
    self
  }

  pub fn ttl_max_servfail(&self) -> &i32 {
    &self.ttl_max_servfail
  }


  pub fn set_ttl_min_noerror(&mut self, ttl_min_noerror: i32) {
    self.ttl_min_noerror = ttl_min_noerror;
  }

  pub fn with_ttl_min_noerror(mut self, ttl_min_noerror: i32) -> NetworkDnscacheSettings {
    self.ttl_min_noerror = ttl_min_noerror;
    self
  }

  pub fn ttl_min_noerror(&self) -> &i32 {
    &self.ttl_min_noerror
  }


  pub fn set_ttl_min_nxdomain(&mut self, ttl_min_nxdomain: i32) {
    self.ttl_min_nxdomain = ttl_min_nxdomain;
  }

  pub fn with_ttl_min_nxdomain(mut self, ttl_min_nxdomain: i32) -> NetworkDnscacheSettings {
    self.ttl_min_nxdomain = ttl_min_nxdomain;
    self
  }

  pub fn ttl_min_nxdomain(&self) -> &i32 {
    &self.ttl_min_nxdomain
  }


  pub fn set_ttl_min_other(&mut self, ttl_min_other: i32) {
    self.ttl_min_other = ttl_min_other;
  }

  pub fn with_ttl_min_other(mut self, ttl_min_other: i32) -> NetworkDnscacheSettings {
    self.ttl_min_other = ttl_min_other;
    self
  }

  pub fn ttl_min_other(&self) -> &i32 {
    &self.ttl_min_other
  }


  pub fn set_ttl_min_servfail(&mut self, ttl_min_servfail: i32) {
    self.ttl_min_servfail = ttl_min_servfail;
  }

  pub fn with_ttl_min_servfail(mut self, ttl_min_servfail: i32) -> NetworkDnscacheSettings {
    self.ttl_min_servfail = ttl_min_servfail;
    self
  }

  pub fn ttl_min_servfail(&self) -> &i32 {
    &self.ttl_min_servfail
  }


}



