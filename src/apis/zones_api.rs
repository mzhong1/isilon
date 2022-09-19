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
use hyper;

use super::{configuration, Error};
#[cfg(feature = "client")]
pub struct ZonesApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect> ZonesApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> ZonesApiClient<C> {
        ZonesApiClient {
            configuration: configuration,
        }
    }
}

pub trait ZonesApi {
    fn create_zone(
        &self,
        zone: crate::models::ZoneCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn delete_zone(&self, zone_id: i32) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn get_zone(
        &self,
        zone_id: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::Zones, Error>>>;
    fn list_zones(&self) -> Box<dyn Future<Output = Result<crate::models::ZonesExtended, Error>>>;
    fn update_zone(
        &self,
        zone: crate::models::Zone,
        zone_id: i32,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
}
#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect + 'static> ZonesApi for ZonesApiClient<C> {
    fn create_zone(
        &self,
        zone: crate::models::ZoneCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!("{}/platform/3/zones", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &zone,
            hyper::Method::POST,
        )
    }

    fn delete_zone(&self, zone_id: i32) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/zones/{ZoneId}",
            self.configuration.base_path,
            ZoneId = zone_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_zone(
        &self,
        zone_id: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::Zones, Error>>> {
        let uri_str = format!(
            "{}/platform/3/zones/{ZoneId}",
            self.configuration.base_path,
            ZoneId = zone_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_zones(&self) -> Box<dyn Future<Output = Result<crate::models::ZonesExtended, Error>>> {
        let uri_str = format!("{}/platform/3/zones", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_zone(
        &self,
        zone: crate::models::Zone,
        zone_id: i32,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/zones/{ZoneId}",
            self.configuration.base_path,
            ZoneId = zone_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &zone,
            hyper::Method::PUT,
        )
    }
}
