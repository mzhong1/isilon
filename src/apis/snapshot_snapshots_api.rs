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

pub struct SnapshotSnapshotsApiClient<C: hyper::client::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::Connect> SnapshotSnapshotsApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> SnapshotSnapshotsApiClient<C> {
        SnapshotSnapshotsApiClient {
            configuration: configuration,
        }
    }
}

pub trait SnapshotSnapshotsApi {
    fn create_snapshot_lock(&self, snapshot_lock: ::models::SnapshotLockCreateParams, sid: &str) -> Box<Future<Item = ::models::CreateSnapshotLockResponse, Error = Error>>;
    fn delete_snapshot_lock(&self, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = (), Error = Error>>;
    fn delete_snapshot_locks(&self, sid: &str) -> Box<Future<Item = (), Error = Error>>;
    fn get_snapshot_lock(&self, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = ::models::SnapshotLocks, Error = Error>>;
    fn list_snapshot_locks(&self, sid: &str, sort: &str, limit: i32, dir: &str, resume: &str) -> Box<Future<Item = ::models::SnapshotLocksExtended, Error = Error>>;
    fn update_snapshot_lock(&self, snapshot_lock: ::models::SnapshotLock, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = (), Error = Error>>;
}


impl<C: hyper::client::Connect>SnapshotSnapshotsApi for SnapshotSnapshotsApiClient<C> {
    fn create_snapshot_lock(&self, snapshot_lock: ::models::SnapshotLockCreateParams, sid: &str) -> Box<Future<Item = ::models::CreateSnapshotLockResponse, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Post;

        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks", configuration.base_path, Sid=sid);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&snapshot_lock).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|body| {
                let parsed: Result<::models::CreateSnapshotLockResponse, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn delete_snapshot_lock(&self, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks/{SnapshotLockId}", configuration.base_path, SnapshotLockId=snapshot_lock_id, Sid=sid);

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
            .and_then(|_| futures::future::ok(()))
        )
    }

    fn delete_snapshot_locks(&self, sid: &str) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Delete;

        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks", configuration.base_path, Sid=sid);

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
            .and_then(|_| futures::future::ok(()))
        )
    }

    fn get_snapshot_lock(&self, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = ::models::SnapshotLocks, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks/{SnapshotLockId}", configuration.base_path, SnapshotLockId=snapshot_lock_id, Sid=sid);

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
                let parsed: Result<::models::SnapshotLocks, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn list_snapshot_locks(&self, sid: &str, sort: &str, limit: i32, dir: &str, resume: &str) -> Box<Future<Item = ::models::SnapshotLocksExtended, Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Get;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks{}", configuration.base_path, query, Sid=sid);

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
                let parsed: Result<::models::SnapshotLocksExtended, _> = serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e))
            }).map_err(|e| Error::from(e))
        )
    }

    fn update_snapshot_lock(&self, snapshot_lock: ::models::SnapshotLock, snapshot_lock_id: &str, sid: &str) -> Box<Future<Item = (), Error = Error>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::Put;

        let uri_str = format!("{}/platform/1/snapshot/snapshots/{Sid}/locks/{SnapshotLockId}", configuration.base_path, SnapshotLockId=snapshot_lock_id, Sid=sid);

        let uri = uri_str.parse();
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }
        let mut req = hyper::Request::new(method, uri.unwrap());


        let serialized = serde_json::to_string(&snapshot_lock).unwrap();
        req.headers_mut().set(hyper::header::ContentType::json());
        req.headers_mut().set(hyper::header::ContentLength(serialized.len() as u64));
        req.set_body(serialized);

        // send request
        Box::new(
            configuration.client.request(req).and_then(|res| { res.body().concat2() })
            .map_err(|e| Error::from(e))
            .and_then(|_| futures::future::ok(()))
        )
    }

}
