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

pub struct AntivirusApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> AntivirusApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> AntivirusApiClient<C> {
        AntivirusApiClient {
            configuration: configuration,
        }
    }
}

pub trait AntivirusApi {
    fn create_antivirus_policy(
        &self,
        antivirus_policy: ::models::AntivirusPolicyCreateParams,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>>;
    fn create_antivirus_scan_item(
        &self,
        antivirus_scan_item: ::models::AntivirusScanItem,
    ) -> Box<Future<Item = ::models::CreateAntivirusScanItemResponse, Error = Error>>;
    fn create_antivirus_server(
        &self,
        antivirus_server: ::models::AntivirusServerCreateParams,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>>;
    fn delete_antivirus_policies(&self) -> Box<Future<Item = (), Error = Error>>;
    fn delete_antivirus_policy(
        &self,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn delete_antivirus_server(
        &self,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn delete_antivirus_servers(&self) -> Box<Future<Item = (), Error = Error>>;
    fn delete_reports_scan(&self, reports_scan_id: &str) -> Box<Future<Item = (), Error = Error>>;
    fn delete_reports_scans(&self, age: i32) -> Box<Future<Item = (), Error = Error>>;
    fn get_antivirus_policy(
        &self,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = ::models::AntivirusPolicies, Error = Error>>;
    fn get_antivirus_quarantine_path(
        &self,
        antivirus_quarantine_path: &str,
    ) -> Box<Future<Item = ::models::AntivirusQuarantine, Error = Error>>;
    fn get_antivirus_server(
        &self,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = ::models::AntivirusServers, Error = Error>>;
    fn get_antivirus_settings(
        &self,
    ) -> Box<Future<Item = ::models::AntivirusSettings, Error = Error>>;
    fn get_reports_scan(
        &self,
        reports_scan_id: &str,
    ) -> Box<Future<Item = ::models::ReportsScans, Error = Error>>;
    fn get_reports_scans(
        &self,
        sort: &str,
        status: &str,
        resume: &str,
        limit: i32,
        dir: &str,
        policy_id: &str,
    ) -> Box<Future<Item = ::models::ReportsScansExtended, Error = Error>>;
    fn get_reports_threat(
        &self,
        reports_threat_id: &str,
    ) -> Box<Future<Item = ::models::ReportsThreats, Error = Error>>;
    fn get_reports_threats(
        &self,
        sort: &str,
        scan_id: &str,
        resume: &str,
        limit: i32,
        file: &str,
        remediation: &str,
        dir: &str,
    ) -> Box<Future<Item = ::models::ReportsThreatsExtended, Error = Error>>;
    fn list_antivirus_policies(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::AntivirusPoliciesExtended, Error = Error>>;
    fn list_antivirus_servers(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::AntivirusServersExtended, Error = Error>>;
    fn update_antivirus_policy(
        &self,
        antivirus_policy: ::models::AntivirusPolicy,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn update_antivirus_quarantine_path(
        &self,
        antivirus_quarantine_path_params: ::models::AntivirusQuarantinePathParams,
        antivirus_quarantine_path: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn update_antivirus_server(
        &self,
        antivirus_server: ::models::AntivirusServer,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>>;
    fn update_antivirus_settings(
        &self,
        antivirus_settings: ::models::AntivirusSettingsSettings,
    ) -> Box<Future<Item = (), Error = Error>>;
}

impl<C: hyper::client::Connect> AntivirusApi for AntivirusApiClient<C> {
    fn create_antivirus_policy(
        &self,
        antivirus_policy: ::models::AntivirusPolicyCreateParams,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/3/antivirus/policies", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_policy).unwrap();
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

    fn create_antivirus_scan_item(
        &self,
        antivirus_scan_item: ::models::AntivirusScanItem,
    ) -> Box<Future<Item = ::models::CreateAntivirusScanItemResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/3/antivirus/scan", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_scan_item).unwrap();
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
                    let parsed: Result<
                        ::models::CreateAntivirusScanItemResponse,
                        _,
                    > = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn create_antivirus_server(
        &self,
        antivirus_server: ::models::AntivirusServerCreateParams,
    ) -> Box<Future<Item = ::models::CreateResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/3/antivirus/servers", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_server).unwrap();
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

    fn delete_antivirus_policies(&self) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!("{}/platform/3/antivirus/policies", configuration.base_path);

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

    fn delete_antivirus_policy(
        &self,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!(
            "{}/platform/3/antivirus/policies/{AntivirusPolicyId}",
            configuration.base_path,
            AntivirusPolicyId = antivirus_policy_id
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

    fn delete_antivirus_server(
        &self,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!(
            "{}/platform/3/antivirus/servers/{AntivirusServerId}",
            configuration.base_path,
            AntivirusServerId = antivirus_server_id
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

    fn delete_antivirus_servers(&self) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!("{}/platform/3/antivirus/servers", configuration.base_path);

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

    fn delete_reports_scan(&self, reports_scan_id: &str) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!(
            "{}/platform/3/antivirus/reports/scans/{ReportsScanId}",
            configuration.base_path,
            ReportsScanId = reports_scan_id
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

    fn delete_reports_scans(&self, age: i32) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("age", &age.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/antivirus/reports/scans?{}",
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
                .and_then(|_| futures::future::ok(())),
        )
    }

    fn get_antivirus_policy(
        &self,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = ::models::AntivirusPolicies, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/antivirus/policies/{AntivirusPolicyId}",
            configuration.base_path,
            AntivirusPolicyId = antivirus_policy_id
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
                    let parsed: Result<::models::AntivirusPolicies, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_antivirus_quarantine_path(
        &self,
        antivirus_quarantine_path: &str,
    ) -> Box<Future<Item = ::models::AntivirusQuarantine, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/antivirus/quarantine/{AntivirusQuarantinePath}",
            configuration.base_path,
            AntivirusQuarantinePath = antivirus_quarantine_path
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
                    let parsed: Result<::models::AntivirusQuarantine, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_antivirus_server(
        &self,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = ::models::AntivirusServers, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/antivirus/servers/{AntivirusServerId}",
            configuration.base_path,
            AntivirusServerId = antivirus_server_id
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
                    let parsed: Result<::models::AntivirusServers, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_antivirus_settings(
        &self,
    ) -> Box<Future<Item = ::models::AntivirusSettings, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/3/antivirus/settings", configuration.base_path);

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
                    let parsed: Result<::models::AntivirusSettings, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_reports_scan(
        &self,
        reports_scan_id: &str,
    ) -> Box<Future<Item = ::models::ReportsScans, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/antivirus/reports/scans/{ReportsScanId}",
            configuration.base_path,
            ReportsScanId = reports_scan_id
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
                    let parsed: Result<::models::ReportsScans, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_reports_scans(
        &self,
        sort: &str,
        status: &str,
        resume: &str,
        limit: i32,
        dir: &str,
        policy_id: &str,
    ) -> Box<Future<Item = ::models::ReportsScansExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("status", &status.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("policy_id", &policy_id.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/antivirus/reports/scans?{}",
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
                    let parsed: Result<::models::ReportsScansExtended, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_reports_threat(
        &self,
        reports_threat_id: &str,
    ) -> Box<Future<Item = ::models::ReportsThreats, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/antivirus/reports/threats/{ReportsThreatId}",
            configuration.base_path,
            ReportsThreatId = reports_threat_id
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
                    let parsed: Result<::models::ReportsThreats, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_reports_threats(
        &self,
        sort: &str,
        scan_id: &str,
        resume: &str,
        limit: i32,
        file: &str,
        remediation: &str,
        dir: &str,
    ) -> Box<Future<Item = ::models::ReportsThreatsExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("scan_id", &scan_id.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("file", &file.to_string())
            .append_pair("remediation", &remediation.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/antivirus/reports/threats?{}",
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
                    let parsed: Result<::models::ReportsThreatsExtended, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn list_antivirus_policies(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::AntivirusPoliciesExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/antivirus/policies?{}",
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
                    let parsed: Result<::models::AntivirusPoliciesExtended, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn list_antivirus_servers(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<Future<Item = ::models::AntivirusServersExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/antivirus/servers?{}",
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
                    let parsed: Result<::models::AntivirusServersExtended, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn update_antivirus_policy(
        &self,
        antivirus_policy: ::models::AntivirusPolicy,
        antivirus_policy_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!(
            "{}/platform/3/antivirus/policies/{AntivirusPolicyId}",
            configuration.base_path,
            AntivirusPolicyId = antivirus_policy_id
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_policy).unwrap();
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

    fn update_antivirus_quarantine_path(
        &self,
        antivirus_quarantine_path_params: ::models::AntivirusQuarantinePathParams,
        antivirus_quarantine_path: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!(
            "{}/platform/3/antivirus/quarantine/{AntivirusQuarantinePath}",
            configuration.base_path,
            AntivirusQuarantinePath = antivirus_quarantine_path
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_quarantine_path_params).unwrap();
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

    fn update_antivirus_server(
        &self,
        antivirus_server: ::models::AntivirusServer,
        antivirus_server_id: &str,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!(
            "{}/platform/3/antivirus/servers/{AntivirusServerId}",
            configuration.base_path,
            AntivirusServerId = antivirus_server_id
        );

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_server).unwrap();
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

    fn update_antivirus_settings(
        &self,
        antivirus_settings: ::models::AntivirusSettingsSettings,
    ) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!("{}/platform/3/antivirus/settings", configuration.base_path);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());
        configuration.set_session(&mut req).unwrap();

        let serialized = serde_json::to_string(&antivirus_settings).unwrap();
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
