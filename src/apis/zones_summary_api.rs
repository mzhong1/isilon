/*
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

use std::borrow::Borrow;
use std::rc::Rc;

use futures;
use futures::Future;

use super::{configuration, Error};

#[cfg(feature = "client")]
pub struct ZonesSummaryApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect> ZonesSummaryApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> ZonesSummaryApiClient<C> {
        ZonesSummaryApiClient {
            configuration: configuration,
        }
    }
}

pub trait ZonesSummaryApi {
    fn get_zones_summary(
        &self,
        groupnet: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::ZonesSummaryExtended, Error>>>;
    fn get_zones_summary_zone(
        &self,
        zones_summary_zone: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::ZonesSummary, Error>>>;
}

#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect + 'static> ZonesSummaryApi for ZonesSummaryApiClient<C> {
    fn get_zones_summary(
        &self,
        groupnet: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::ZonesSummaryExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("groupnet", &groupnet.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/zones-summary?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_zones_summary_zone(
        &self,
        zones_summary_zone: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::ZonesSummary, Error>>> {
        let uri_str = format!(
            "{}/platform/1/zones-summary/{ZonesSummaryZone}",
            self.configuration.base_path,
            ZonesSummaryZone = zones_summary_zone
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }
}
