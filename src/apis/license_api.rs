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

pub struct LicenseApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> LicenseApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> LicenseApiClient<C> {
        LicenseApiClient {
            configuration: configuration,
        }
    }
}

pub trait LicenseApi {
    fn create_license_license(&self, license_license: ::models::LicenseLicenseCreateParams) -> Box<Future<Item = ::models::Empty, Error = Error>>;
    fn get_license_generate(&self, action: &str, licenses_to_include: &str, licenses_to_exclude: &str, only_these_licenses: &str) -> Box<Future<Item = ::models::LicenseGenerate, Error = Error>>;
    fn get_license_license(&self, license_license_id: &str) -> Box<Future<Item = ::models::LicenseLicenses, Error = Error>>;
    fn list_license_licenses(&self, ) -> Box<Future<Item = ::models::LicenseLicensesExtended, Error = Error>>;
}


impl<C: hyper::client::Connect>LicenseApi for LicenseApiClient<C> {
    fn create_license_license(&self, license_license: ::models::LicenseLicenseCreateParams) -> Box<Future<Item = ::models::Empty, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/5/license/licenses", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&license_license).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::Empty, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn get_license_generate(&self, action: &str, licenses_to_include: &str, licenses_to_exclude: &str, only_these_licenses: &str) -> Box<Future<Item = ::models::LicenseGenerate, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("action", &action.to_string())
            .append_pair("licenses_to_include", &licenses_to_include.to_string())
            .append_pair("licenses_to_exclude", &licenses_to_exclude.to_string())
            .append_pair("only_these_licenses", &only_these_licenses.to_string())
            .finish();
        let uri_str = format!("{}/platform/5/license/generate{}", configuration.base_path, query);

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
                let parsed: Result<::models::LicenseGenerate, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn get_license_license(&self, license_license_id: &str) -> Box<Future<Item = ::models::LicenseLicenses, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/5/license/licenses/{LicenseLicenseId}", configuration.base_path, LicenseLicenseId=license_license_id);

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
                let parsed: Result<::models::LicenseLicenses, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn list_license_licenses(&self, ) -> Box<Future<Item = ::models::LicenseLicensesExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/5/license/licenses", configuration.base_path);

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
                let parsed: Result<::models::LicenseLicensesExtended, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

}
