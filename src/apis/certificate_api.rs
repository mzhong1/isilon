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

use super::{configuration, put, query, Error};

pub struct CertificateApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> CertificateApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> CertificateApiClient<C> {
        CertificateApiClient {
            configuration: configuration,
        }
    }
}

pub trait CertificateApi {
    fn create_certificate_server_item(
        &self,
        certificate_server_item: crate::models::CertificateServerItem,
    ) -> Result<crate::models::CreateResponse, Error>;
    fn delete_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Result<(), Error>;
    fn get_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Result<crate::models::CertificateServer, Error>;
    fn list_certificate_server(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::CertificateServerExtended, Error>;
    fn update_certificate_server_by_id(
        &self,
        certificate_server_id_params: crate::models::CertificateServerIdParams,
        certificate_server_id: &str,
    ) -> Result<(), Error>;
}

impl<C: hyper::client::connect::Connect + 'static + std::marker::Sync + std::marker::Send + Clone> CertificateApi for CertificateApiClient<C> {
    fn create_certificate_server_item(
        &self,
        certificate_server_item: crate::models::CertificateServerItem,
    ) -> Result<crate::models::CreateResponse, Error> {
        let uri_str = format!(
            "{}/platform/4/certificate/server",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &certificate_server_item,
            hyper::Method::POST,
        )
    }

    fn delete_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Result<(), Error>{
        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            self.configuration.base_path,
            CertificateServerId = certificate_server_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_certificate_server_by_id(
        &self,
        certificate_server_id: &str,
    ) -> Result<crate::models::CertificateServer, Error> {
        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            self.configuration.base_path,
            CertificateServerId = certificate_server_id
        );
        // let parsed: Result <crate::models::CertificateServer, _> =
        //     serde_json::from_slice(&body);
        query(
            self.configuration.borrow(),
            &uri_str,
            &certificate_server_id,
            hyper::Method::GET,
        )
    }

    fn list_certificate_server(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::CertificateServerExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/certificate/server?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_certificate_server_by_id(
        &self,
        certificate_server_id_params: crate::models::CertificateServerIdParams,
        certificate_server_id: &str,
    ) -> Result<(), Error>{
        let uri_str = format!(
            "{}/platform/4/certificate/server/{CertificateServerId}",
            self.configuration.base_path,
            CertificateServerId = certificate_server_id
        );

        put(
            self.configuration.borrow(),
            &uri_str,
            &certificate_server_id_params,
        )
    }
}
