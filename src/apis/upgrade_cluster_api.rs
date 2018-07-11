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
use futures::{Future, Stream};
use hyper;
use serde_json;

use super::{configuration, Error};

pub struct UpgradeClusterApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> UpgradeClusterApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> UpgradeClusterApiClient<C> {
        UpgradeClusterApiClient {
            configuration: configuration,
        }
    }
}

pub trait UpgradeClusterApi {
    fn create_nodes_node_patch_sync_item(
        &self,
        nodes_node_patch_sync_item: ::models::Empty,
        lnn: i32,
    ) -> Box<Future<Item = ::models::Empty, Error = Error>>;
    fn get_nodes_node_firmware_status(
        &self,
        lnn: i32,
        devices: bool,
        package: bool,
    ) -> Box<Future<Item = ::models::NodesNodeFirmwareStatus, Error = Error>>;
}

impl<C: hyper::client::Connect> UpgradeClusterApi for UpgradeClusterApiClient<C> {
    fn create_nodes_node_patch_sync_item(
        &self,
        nodes_node_patch_sync_item: ::models::Empty,
        lnn: i32,
    ) -> Box<Future<Item = ::models::Empty, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!(
            "{}/platform/4/upgrade/cluster/nodes/{Lnn}/patch/sync",
            configuration.base_path,
            Lnn = lnn
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&nodes_node_patch_sync_item).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut()
            .set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration
                .client
                .request(req)
                .and_then(|res| res.body().concat2())
                .map_err(|e| Error::from(e))
                .and_then(|body| {
                    let parsed: Result<::models::Empty, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_nodes_node_firmware_status(
        &self,
        lnn: i32,
        devices: bool,
        package: bool,
    ) -> Box<Future<Item = ::models::NodesNodeFirmwareStatus, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("devices", &devices.to_string())
            .append_pair("package", &package.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/upgrade/cluster/nodes/{Lnn}/firmware/status?{}",
            configuration.base_path,
            query,
            Lnn = lnn
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        // send request
        Box::new(
            configuration
                .client
                .request(req)
                .and_then(|res| res.body().concat2())
                .map_err(|e| Error::from(e))
                .and_then(|body| {
                    let parsed: Result<::models::NodesNodeFirmwareStatus, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }
}
