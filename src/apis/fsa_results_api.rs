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

pub struct FsaResultsApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> FsaResultsApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> FsaResultsApiClient<C> {
        FsaResultsApiClient {
            configuration: configuration,
        }
    }
}

pub trait FsaResultsApi {
    fn get_histogram_stat_by(
        &self,
        id: &str,
        stat: &str,
    ) -> Box<Future<Item = ::models::HistogramStatBy, Error = Error>>;
    fn get_histogram_stat_by_breakout(
        &self,
        histogram_stat_by_breakout: &str,
        id: &str,
        stat: &str,
        directory_filter: &str,
        attribute_filter: &str,
        node_pool_filter: &str,
        disk_pool_filter: &str,
        tier_filter: &str,
        comp_report: i32,
        log_size_filter: i32,
        phys_size_filter: i32,
        limit: i32,
        path_ext_filter: &str,
        ctime_filter: i32,
        atime_filter: i32,
    ) -> Box<Future<Item = ::models::HistogramStatBy, Error = Error>>;
    fn get_result_directories(
        &self,
        id: &str,
        sort: &str,
        path: &str,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultDirectories, Error = Error>>;
    fn get_result_directory(
        &self,
        result_directory_id: i32,
        id: &str,
        sort: &str,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultDirectories, Error = Error>>;
    fn get_result_histogram(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultHistogram, Error = Error>>;
    fn get_result_histogram_stat(
        &self,
        result_histogram_stat: &str,
        id: &str,
        directory_filter: &str,
        attribute_filter: &str,
        node_pool_filter: &str,
        disk_pool_filter: &str,
        tier_filter: &str,
        comp_report: i32,
        log_size_filter: i32,
        phys_size_filter: i32,
        path_ext_filter: &str,
        ctime_filter: i32,
        atime_filter: i32,
    ) -> Box<Future<Item = ::models::ResultHistogram, Error = Error>>;
    fn get_result_top_dir(
        &self,
        result_top_dir_id: &str,
        id: &str,
        sort: &str,
        start: i32,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultTopDirs, Error = Error>>;
    fn get_result_top_dirs(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultTopDirs, Error = Error>>;
    fn get_result_top_file(
        &self,
        result_top_file_id: &str,
        id: &str,
        sort: &str,
        start: i32,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultTopFiles, Error = Error>>;
    fn get_result_top_files(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultTopFiles, Error = Error>>;
}

impl<C: hyper::client::Connect> FsaResultsApi for FsaResultsApiClient<C> {
    fn get_histogram_stat_by(
        &self,
        id: &str,
        stat: &str,
    ) -> Box<Future<Item = ::models::HistogramStatBy, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/histogram/{Stat}/by",
            configuration.base_path,
            Id = id,
            Stat = stat
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
                    let parsed: Result<::models::HistogramStatBy, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_histogram_stat_by_breakout(
        &self,
        histogram_stat_by_breakout: &str,
        id: &str,
        stat: &str,
        directory_filter: &str,
        attribute_filter: &str,
        node_pool_filter: &str,
        disk_pool_filter: &str,
        tier_filter: &str,
        comp_report: i32,
        log_size_filter: i32,
        phys_size_filter: i32,
        limit: i32,
        path_ext_filter: &str,
        ctime_filter: i32,
        atime_filter: i32,
    ) -> Box<Future<Item = ::models::HistogramStatBy, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("directory_filter", &directory_filter.to_string())
            .append_pair("attribute_filter", &attribute_filter.to_string())
            .append_pair("node_pool_filter", &node_pool_filter.to_string())
            .append_pair("disk_pool_filter", &disk_pool_filter.to_string())
            .append_pair("tier_filter", &tier_filter.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("log_size_filter", &log_size_filter.to_string())
            .append_pair("phys_size_filter", &phys_size_filter.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("path_ext_filter", &path_ext_filter.to_string())
            .append_pair("ctime_filter", &ctime_filter.to_string())
            .append_pair("atime_filter", &atime_filter.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/histogram/{Stat}/by/{HistogramStatByBreakout}?{}",
            configuration.base_path,
            query,
            HistogramStatByBreakout = histogram_stat_by_breakout,
            Id = id,
            Stat = stat
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
                    let parsed: Result<::models::HistogramStatBy, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_directories(
        &self,
        id: &str,
        sort: &str,
        path: &str,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultDirectories, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("path", &path.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/directories?{}",
            configuration.base_path,
            query,
            Id = id
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
                    let parsed: Result<::models::ResultDirectories, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_directory(
        &self,
        result_directory_id: i32,
        id: &str,
        sort: &str,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultDirectories, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/directories/{ResultDirectoryId}?{}",
            configuration.base_path,
            query,
            ResultDirectoryId = result_directory_id,
            Id = id
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
                    let parsed: Result<::models::ResultDirectories, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_histogram(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultHistogram, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/histogram",
            configuration.base_path,
            Id = id
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
                    let parsed: Result<::models::ResultHistogram, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_histogram_stat(
        &self,
        result_histogram_stat: &str,
        id: &str,
        directory_filter: &str,
        attribute_filter: &str,
        node_pool_filter: &str,
        disk_pool_filter: &str,
        tier_filter: &str,
        comp_report: i32,
        log_size_filter: i32,
        phys_size_filter: i32,
        path_ext_filter: &str,
        ctime_filter: i32,
        atime_filter: i32,
    ) -> Box<Future<Item = ::models::ResultHistogram, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("directory_filter", &directory_filter.to_string())
            .append_pair("attribute_filter", &attribute_filter.to_string())
            .append_pair("node_pool_filter", &node_pool_filter.to_string())
            .append_pair("disk_pool_filter", &disk_pool_filter.to_string())
            .append_pair("tier_filter", &tier_filter.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("log_size_filter", &log_size_filter.to_string())
            .append_pair("phys_size_filter", &phys_size_filter.to_string())
            .append_pair("path_ext_filter", &path_ext_filter.to_string())
            .append_pair("ctime_filter", &ctime_filter.to_string())
            .append_pair("atime_filter", &atime_filter.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/histogram/{ResultHistogramStat}?{}",
            configuration.base_path,
            query,
            ResultHistogramStat = result_histogram_stat,
            Id = id
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
                    let parsed: Result<::models::ResultHistogram, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_top_dir(
        &self,
        result_top_dir_id: &str,
        id: &str,
        sort: &str,
        start: i32,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultTopDirs, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("start", &start.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/top-dirs/{ResultTopDirId}?{}",
            configuration.base_path,
            query,
            ResultTopDirId = result_top_dir_id,
            Id = id
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
                    let parsed: Result<::models::ResultTopDirs, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_top_dirs(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultTopDirs, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/top-dirs",
            configuration.base_path,
            Id = id
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
                    let parsed: Result<::models::ResultTopDirs, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_top_file(
        &self,
        result_top_file_id: &str,
        id: &str,
        sort: &str,
        start: i32,
        limit: i32,
        comp_report: i32,
        dir: &str,
    ) -> Box<Future<Item = ::models::ResultTopFiles, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("start", &start.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("comp_report", &comp_report.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/top-files/{ResultTopFileId}?{}",
            configuration.base_path,
            query,
            ResultTopFileId = result_top_file_id,
            Id = id
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
                    let parsed: Result<::models::ResultTopFiles, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }

    fn get_result_top_files(
        &self,
        id: &str,
    ) -> Box<Future<Item = ::models::ResultTopFiles, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!(
            "{}/platform/3/fsa/results/{Id}/top-files",
            configuration.base_path,
            Id = id
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
                    let parsed: Result<::models::ResultTopFiles, _> = serde_json::from_slice(&body);
                    parsed.map_err(|e| Error::from(e))
                })
                .map_err(|e| Error::from(e)),
        )
    }
}
