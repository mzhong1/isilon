/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

use std::rc::Rc;
use std::borrow::Borrow;

use hyper;
use serde_json;
use futures;
use futures::{Future, Stream};

use super::{Error, configuration};

pub struct HardeningApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> HardeningApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> HardeningApiClient<C> {
        HardeningApiClient {
            configuration: configuration,
        }
    }
}

pub trait HardeningApi {
    fn create_hardening_apply_item(&self, hardening_apply_item: ::models::HardeningApplyItem) -> Box<Future<Item = ::models::CreateHardeningApplyItemResponse, Error = Error>>;
    fn create_hardening_resolve_item(&self, hardening_resolve_item: ::models::HardeningResolveItem, accept: bool) -> Box<Future<Item = ::models::CreateHardeningResolveItemResponse, Error = Error>>;
    fn create_hardening_revert_item(&self, hardening_revert_item: ::models::Empty, force: bool) -> Box<Future<Item = ::models::CreateHardeningRevertItemResponse, Error = Error>>;
    fn get_hardening_state(&self, ) -> Box<Future<Item = ::models::HardeningState, Error = Error>>;
    fn get_hardening_status(&self, ) -> Box<Future<Item = ::models::HardeningStatus, Error = Error>>;
}


impl<C: hyper::client::Connect>HardeningApi for HardeningApiClient<C> {
    fn create_hardening_apply_item(&self, hardening_apply_item: ::models::HardeningApplyItem) -> Box<Future<Item = ::models::CreateHardeningApplyItemResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/3/hardening/apply", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&hardening_apply_item).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::CreateHardeningApplyItemResponse, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn create_hardening_resolve_item(&self, hardening_resolve_item: ::models::HardeningResolveItem, accept: bool) -> Box<Future<Item = ::models::CreateHardeningResolveItemResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("accept", &accept.to_string())
            .finish();
        let uri_str = format!("{}/platform/3/hardening/resolve{}", configuration.base_path, query);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&hardening_resolve_item).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::CreateHardeningResolveItemResponse, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn create_hardening_revert_item(&self, hardening_revert_item: ::models::Empty, force: bool) -> Box<Future<Item = ::models::CreateHardeningRevertItemResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("force", &force.to_string())
            .finish();
        let uri_str = format!("{}/platform/3/hardening/revert{}", configuration.base_path, query);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&hardening_revert_item).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::CreateHardeningRevertItemResponse, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn get_hardening_state(&self, ) -> Box<Future<Item = ::models::HardeningState, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/3/hardening/state", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());



        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::HardeningState, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn get_hardening_status(&self, ) -> Box<Future<Item = ::models::HardeningStatus, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/3/hardening/status", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());



        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::HardeningStatus, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

}
