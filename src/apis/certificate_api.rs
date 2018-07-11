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

pub struct CertificateApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> CertificateApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> CertificateApiClient<C> {
        CertificateApiClient {
            configuration: configuration,
        }
    }
}

pub trait CertificateApi {
    fn create_certificate_server_item(
        &self,
        certificate_server_item: ::models::CertificateServerItem,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>>;
    fn delete_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn get_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Box<Future<Item = ::models::CertificateServer, Error = Error>>;
    fn list_certificate_server(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::CertificateServerExtended, Error = Error>>;
    fn update_certificate_server_by_id(
        &self,
        certificate_server_id_params: ::models::CertificateServerIdParams,
        certificate_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
}

impl<C: hyper::client::Connect> CertificateApi for CertificateApiClient<C> {
    fn create_certificate_server_item(
        &self,
        certificate_server_item: ::models::CertificateServerItem,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/4/certificate/server", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&certificate_server_item).unwrap();
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
                    let parsed: Result<::models::CreateResponse, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn delete_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            configuration.base_path,
            CertificateServerId = certificate_server_id
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
                .and_then(|_| futures::future::ok(())),
        )
    }

    fn get_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Box<Future<Item = ::models::CertificateServer, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            configuration.base_path,
            CertificateServerId = certificate_server_id
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
                    let parsed: Result<::models::CertificateServer, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn list_certificate_server(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::CertificateServerExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/certificate/server?{}",
            configuration.base_path, query
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
                    let parsed: Result<::models::CertificateServerExtended, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn update_certificate_server_by_id(
        &self,
        certificate_server_id_params: ::models::CertificateServerIdParams,
        certificate_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            configuration.base_path,
            CertificateServerId = certificate_server_id
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&certificate_server_id_params).unwrap();
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
                .and_then(|_| futures::future::ok(())),
        )
    }
}
