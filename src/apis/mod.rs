use cookie;
use futures::{Future, Stream};
#[cfg(feature = "client")]
use hyper::{self, client::connect::Connect, header::HeaderName, header::HeaderValue, Request};
use reqwest;
use serde::{de::DeserializeOwned, Serialize};
use serde_json;

use std::collections::HashMap;
use std::error::Error as err;
use std::io;

#[derive(Debug)]
pub enum Error {
    E(String),
    Cookie(cookie::ParseError),
    Hyper(hyper::Error),
    Io(io::Error),
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    /// Session token needs to be recreated.  Call Configuration::login
    SessionExpired,
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        f.write_str(self.description())
    }
}

impl err for Error {
    fn description(&self) -> &str {
        match *self {
            Error::E(ref s) => s,
            Error::Cookie(ref e) => e.description(),
            Error::Hyper(ref e) => e.description(),
            Error::Io(ref e) => e.description(),
            Error::Reqwest(ref e) => e.description(),
            Error::Serde(ref e) => e.description(),
            Error::SessionExpired => "Session Expired",
        }
    }

    fn cause(&self) -> Option<&dyn ::std::error::Error> {
        match *self {
            Error::E(_) => None,
            Error::Cookie(ref e) => e.cause(),
            Error::Hyper(ref e) => e.cause(),
            Error::Io(ref e) => e.cause(),
            Error::Reqwest(ref e) => e.cause(),
            Error::Serde(ref e) => e.cause(),
            Error::SessionExpired => None,
        }
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        return Error::E(e);
    }
}

impl From<cookie::ParseError> for Error {
    fn from(e: cookie::ParseError) -> Self {
        return Error::Cookie(e);
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        return Error::Hyper(e);
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        return Error::Io(e);
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        return Error::Reqwest(e);
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        return Error::Serde(e);
    }
}

mod antivirus_api;
pub use self::antivirus_api::AntivirusApi;
mod audit_api;
pub use self::audit_api::AuditApi;
mod auth_api;
pub use self::auth_api::AuthApi;
mod auth_groups_api;
pub use self::auth_groups_api::AuthGroupsApi;
mod auth_providers_api;
pub use self::auth_providers_api::AuthProvidersApi;
mod auth_roles_api;
pub use self::auth_roles_api::AuthRolesApi;
mod auth_users_api;
pub use self::auth_users_api::AuthUsersApi;
mod certificate_api;
pub use self::certificate_api::CertificateApi;
mod cloud_api;
pub use self::cloud_api::CloudApi;
mod cluster_api;
pub use self::cluster_api::ClusterApi;
mod cluster_nodes_api;
pub use self::cluster_nodes_api::ClusterNodesApi;
mod debug_api;
pub use self::debug_api::DebugApi;
mod dedupe_api;
pub use self::dedupe_api::DedupeApi;
mod event_api;
pub use self::event_api::EventApi;
mod file_filter_api;
pub use self::file_filter_api::FileFilterApi;
mod filepool_api;
pub use self::filepool_api::FilepoolApi;
mod filesystem_api;
pub use self::filesystem_api::FilesystemApi;
mod fsa_api;
pub use self::fsa_api::FsaApi;
mod fsa_results_api;
pub use self::fsa_results_api::FsaResultsApi;
mod hardening_api;
pub use self::hardening_api::HardeningApi;
mod hardware_api;
pub use self::hardware_api::HardwareApi;
mod id_resolution_api;
pub use self::id_resolution_api::IdResolutionApi;
mod job_api;
pub use self::job_api::JobApi;
mod license_api;
pub use self::license_api::LicenseApi;
mod local_api;
pub use self::local_api::LocalApi;
mod namespace_api;
pub use self::namespace_api::NamespaceApi;
mod network_api;
pub use self::network_api::NetworkApi;
mod network_groupnets_api;
pub use self::network_groupnets_api::NetworkGroupnetsApi;
mod network_groupnets_subnets_api;
pub use self::network_groupnets_subnets_api::NetworkGroupnetsSubnetsApi;
mod protocols_api;
pub use self::protocols_api::ProtocolsApi;
mod protocols_hdfs_api;
pub use self::protocols_hdfs_api::ProtocolsHdfsApi;
mod quota_api;
pub use self::quota_api::QuotaApi;
mod quota_quotas_api;
pub use self::quota_quotas_api::QuotaQuotasApi;
mod quota_reports_api;
pub use self::quota_reports_api::QuotaReportsApi;
mod remotesupport_api;
pub use self::remotesupport_api::RemotesupportApi;
mod snapshot_api;
pub use self::snapshot_api::SnapshotApi;
mod snapshot_changelists_api;
pub use self::snapshot_changelists_api::SnapshotChangelistsApi;
mod snapshot_snapshots_api;
pub use self::snapshot_snapshots_api::SnapshotSnapshotsApi;
mod statistics_api;
pub use self::statistics_api::StatisticsApi;
mod storagepool_api;
pub use self::storagepool_api::StoragepoolApi;
mod sync_api;
pub use self::sync_api::SyncApi;
mod sync_policies_api;
pub use self::sync_policies_api::SyncPoliciesApi;
mod sync_reports_api;
pub use self::sync_reports_api::SyncReportsApi;
mod sync_target_api;
pub use self::sync_target_api::SyncTargetApi;
mod upgrade_api;
pub use self::upgrade_api::UpgradeApi;
mod upgrade_cluster_api;
pub use self::upgrade_cluster_api::UpgradeClusterApi;
mod worm_api;
pub use self::worm_api::WormApi;
mod zones_api;
pub use self::zones_api::ZonesApi;
mod zones_summary_api;
pub use self::zones_summary_api::ZonesSummaryApi;

pub mod client;
pub mod configuration;

#[cfg(feature = "client")]
fn query<T, R, C: hyper::client::connect::Connect + 'static>(
    config: &configuration::Configuration<C>,
    url: &str,
    body: &T,
    method: hyper::Method,
) -> Box<dyn Future<Output = Result<R, Error>>>
where
    T: Serialize,
    R: DeserializeOwned + 'static,
{
    let serialized = serde_json::to_string(&body).unwrap();
    let body = hyper::Body::from(serialized);
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(url)
        .header(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("Application/json"),
        )
        .body(body)
        .unwrap();
    config.set_session(&mut req).unwrap();

    Box::new(
        config
            .client
            .request(req)
            .and_then(|res| res.into_body().concat2())
            .map_err(|e| Error::from(e))
            .and_then(|ref body| {
                let parsed: Result<R, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            })
            .map_err(|e| Error::from(e)),
    )
}

#[cfg(feature = "client")]
fn put<T, C: hyper::client::connect::Connect + 'static>(
    config: &configuration::Configuration<C>,
    url: &str,
    body: &T,
) -> Box<dyn Future<Output = Result<(), Error>>>
where
    T: Serialize,
{
    let serialized = serde_json::to_string(&body).unwrap();
    let body = hyper::Body::from(serialized);
    let mut req = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(url)
        .header(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("Application/json"),
        )
        .body(body)
        .unwrap();
    config.set_session(&mut req).unwrap();

    Box::new(
        config
            .client
            .request(req)
            .and_then(|res| res.into_body().concat2())
            .map_err(|e| Error::from(e))
            .and_then(|_| futures::future::ok(())),
    )
}

#[cfg(feature = "client")]
fn custom_query<T, R, C: hyper::client::connect::Connect + 'static>(
    config: &configuration::Configuration<C>,
    url: &str,
    body: &T,
    method: hyper::Method,
    headers: HashMap<String, String>,
) -> Box<dyn Future<Output = Result<R, Error>>>
where
    T: Serialize,
    R: DeserializeOwned + 'static,
{
    let serialized = serde_json::to_string(&body).unwrap();
    let body = hyper::Body::from(serialized.clone());
    let mut req = hyper::Request::builder();
    req.method(method);
    req.uri(url);
    req.header(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("Application/json"),
    );
    for (key, value) in headers {
        req.header(
            hyper::header::HeaderName::from_bytes(&key.as_bytes()).unwrap(),
            hyper::header::HeaderValue::from_str(&value).unwrap(),
        );
    }

    let mut req = req.body(body).unwrap();
    config.set_session(&mut req).unwrap();

    Box::new(
        config
            .client
            .request(req)
            .and_then(|res| res.into_body().concat2())
            .map_err(|e| Error::from(e))
            .and_then(|ref body| {
                let parsed: Result<R, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            })
            .map_err(|e| Error::from(e)),
    )
}
