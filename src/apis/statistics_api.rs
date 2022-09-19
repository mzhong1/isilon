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
pub struct StatisticsApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}
#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect> StatisticsApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> StatisticsApiClient<C> {
        StatisticsApiClient {
            configuration: configuration,
        }
    }
}

pub trait StatisticsApi {
    fn get_statistics_current(
        &self,
        timeout: i32,
        show_nodes: bool,
        keys: Vec<String>,
        devid: Vec<String>,
        substr: bool,
        stale: bool,
        type_info: bool,
        raw: bool,
        key: Vec<String>,
        degraded: bool,
        nodes: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsCurrent, Error>>>;
    fn get_statistics_history(
        &self,
        begin: i32,
        interval: i32,
        end: i32,
        timeout: i32,
        raw: bool,
        keys: Vec<String>,
        devid: Vec<String>,
        substr: bool,
        stale: bool,
        type_info: bool,
        memory_only: bool,
        key: Vec<String>,
        degraded: bool,
        show_nodes: bool,
        resolution: i32,
        nodes: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsHistory, Error>>>;
    fn get_statistics_key(
        &self,
        statistics_key_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsKeys, Error>>>;
    fn get_statistics_keys(
        &self,
        count: bool,
        limit: i32,
        queryable: bool,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsKeysExtended, Error>>>;
    fn get_statistics_operations(
        &self,
        protocols: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsOperations, Error>>>;
    fn get_statistics_protocols(
        &self,
        _type: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsProtocols, Error>>>;
    fn get_summary_client(
        &self,
        sort: &str,
        totalby: &str,
        user_names: &str,
        remote_addresses: &str,
        numeric: bool,
        local_names: &str,
        user_ids: &str,
        classes: &str,
        timeout: i32,
        local_addresses: &str,
        degraded: bool,
        remote_names: &str,
        nodes: &str,
        protocols: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryClient, Error>>>;
    fn get_summary_drive(
        &self,
        sort: &str,
        degraded: bool,
        _type: &str,
        nodes: &str,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryDrive, Error>>>;
    fn get_summary_heat(
        &self,
        sort: &str,
        convertlin: bool,
        totalby: &str,
        pathdepth: i32,
        numeric: bool,
        events: &str,
        maxpath: i32,
        classes: &str,
        timeout: i32,
        nodes: &str,
        degraded: bool,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryHeat, Error>>>;
    fn get_summary_protocol(
        &self,
        operations: &str,
        sort: &str,
        totalby: &str,
        zero: bool,
        classes: &str,
        timeout: i32,
        degraded: bool,
        nodes: &str,
        protocols: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryProtocol, Error>>>;
    fn get_summary_protocol_stats(
        &self,
        degraded: bool,
        protocol: Option<&str>,
        nodes: Option<&str>,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryProtocolStats, Error>>>;
    fn get_summary_system(
        &self,
        sort: &str,
        oprates: bool,
        degraded: bool,
        nodes: &str,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummarySystem, Error>>>;
    fn get_summary_workload(
        &self,
        sort: &str,
        job_types: Vec<String>,
        totalby: &str,
        timeout: i32,
        degraded: bool,
        nodes: &str,
        system_names: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryWorkload, Error>>>;
}
#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect + 'static> StatisticsApi for StatisticsApiClient<C> {
    fn get_statistics_current(
        &self,
        timeout: i32,
        show_nodes: bool,
        keys: Vec<String>,
        devid: Vec<String>,
        substr: bool,
        stale: bool,
        type_info: bool,
        raw: bool,
        key: Vec<String>,
        degraded: bool,
        nodes: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsCurrent, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("show_nodes", &show_nodes.to_string())
            .append_pair("keys", &keys.join(",").to_string())
            .append_pair("devid", &devid.join(",").to_string())
            .append_pair("substr", &substr.to_string())
            .append_pair("stale", &stale.to_string())
            .append_pair("type_info", &type_info.to_string())
            .append_pair("raw", &raw.to_string())
            .append_pair("key", &key.join(",").to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("nodes", &nodes.join(",").to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/statistics/current?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_statistics_history(
        &self,
        begin: i32,
        interval: i32,
        end: i32,
        timeout: i32,
        raw: bool,
        keys: Vec<String>,
        devid: Vec<String>,
        substr: bool,
        stale: bool,
        type_info: bool,
        memory_only: bool,
        key: Vec<String>,
        degraded: bool,
        show_nodes: bool,
        resolution: i32,
        nodes: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsHistory, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("begin", &begin.to_string())
            .append_pair("interval", &interval.to_string())
            .append_pair("end", &end.to_string())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("raw", &raw.to_string())
            .append_pair("keys", &keys.join(",").to_string())
            .append_pair("devid", &devid.join(",").to_string())
            .append_pair("substr", &substr.to_string())
            .append_pair("stale", &stale.to_string())
            .append_pair("type_info", &type_info.to_string())
            .append_pair("memory_only", &memory_only.to_string())
            .append_pair("key", &key.join(",").to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("show_nodes", &show_nodes.to_string())
            .append_pair("resolution", &resolution.to_string())
            .append_pair("nodes", &nodes.join(",").to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/statistics/history?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_statistics_key(
        &self,
        statistics_key_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsKeys, Error>>> {
        let uri_str = format!(
            "{}/platform/1/statistics/keys/{StatisticsKeyId}",
            self.configuration.base_path,
            StatisticsKeyId = statistics_key_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_statistics_keys(
        &self,
        count: bool,
        limit: i32,
        queryable: bool,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsKeysExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("count", &count.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("queryable", &queryable.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/statistics/keys?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_statistics_operations(
        &self,
        protocols: Vec<String>,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsOperations, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("protocols", &protocols.join(",").to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/operations?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_statistics_protocols(
        &self,
        _type: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::StatisticsProtocols, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("type", &_type.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/statistics/protocols?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_client(
        &self,
        sort: &str,
        totalby: &str,
        user_names: &str,
        remote_addresses: &str,
        numeric: bool,
        local_names: &str,
        user_ids: &str,
        classes: &str,
        timeout: i32,
        local_addresses: &str,
        degraded: bool,
        remote_names: &str,
        nodes: &str,
        protocols: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryClient, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("totalby", &totalby.to_string())
            .append_pair("user_names", &user_names.to_string())
            .append_pair("remote_addresses", &remote_addresses.to_string())
            .append_pair("numeric", &numeric.to_string())
            .append_pair("local_names", &local_names.to_string())
            .append_pair("user_ids", &user_ids.to_string())
            .append_pair("classes", &classes.to_string())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("local_addresses", &local_addresses.to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("remote_names", &remote_names.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("protocols", &protocols.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/summary/client?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_drive(
        &self,
        sort: &str,
        degraded: bool,
        _type: &str,
        nodes: &str,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryDrive, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("type", &_type.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("timeout", &timeout.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/summary/drive?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_heat(
        &self,
        sort: &str,
        convertlin: bool,
        totalby: &str,
        pathdepth: i32,
        numeric: bool,
        events: &str,
        maxpath: i32,
        classes: &str,
        timeout: i32,
        nodes: &str,
        degraded: bool,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryHeat, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("convertlin", &convertlin.to_string())
            .append_pair("totalby", &totalby.to_string())
            .append_pair("pathdepth", &pathdepth.to_string())
            .append_pair("numeric", &numeric.to_string())
            .append_pair("events", &events.to_string())
            .append_pair("maxpath", &maxpath.to_string())
            .append_pair("classes", &classes.to_string())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("degraded", &degraded.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/summary/heat?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_protocol(
        &self,
        operations: &str,
        sort: &str,
        totalby: &str,
        zero: bool,
        classes: &str,
        timeout: i32,
        degraded: bool,
        nodes: &str,
        protocols: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryProtocol, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("operations", &operations.to_string())
            .append_pair("sort", &sort.to_string())
            .append_pair("totalby", &totalby.to_string())
            .append_pair("zero", &zero.to_string())
            .append_pair("classes", &classes.to_string())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("protocols", &protocols.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/summary/protocol?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_protocol_stats(
        &self,
        degraded: bool,
        protocol: Option<&str>,
        nodes: Option<&str>,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryProtocolStats, Error>>> {
        let buff = String::new();
        let mut q = ::url::form_urlencoded::Serializer::new(buff);
        q.append_pair("degraded", &degraded.to_string());
        q.append_pair("timeout", &timeout.to_string());
        if let Some(protocol) = protocol {
            q.append_pair("protocol", &protocol.to_string());
        }
        if let Some(nodes) = nodes {
            q.append_pair("nodes", &nodes.to_string());
        }
        let q = q.finish();

        let uri_str = format!(
            "{}/platform/3/statistics/summary/protocol-stats?{}",
            self.configuration.base_path, q
        );
        debug!("summary_protocol uri_str: {}", uri_str);
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_system(
        &self,
        sort: &str,
        oprates: bool,
        degraded: bool,
        nodes: &str,
        timeout: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::SummarySystem, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("oprates", &oprates.to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("timeout", &timeout.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/statistics/summary/system?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_summary_workload(
        &self,
        sort: &str,
        job_types: Vec<String>,
        totalby: &str,
        timeout: i32,
        degraded: bool,
        nodes: &str,
        system_names: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SummaryWorkload, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("job_types", &job_types.join(",").to_string())
            .append_pair("totalby", &totalby.to_string())
            .append_pair("timeout", &timeout.to_string())
            .append_pair("degraded", &degraded.to_string())
            .append_pair("nodes", &nodes.to_string())
            .append_pair("system_names", &system_names.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/statistics/summary/workload?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }
}
