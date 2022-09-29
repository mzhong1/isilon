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

pub struct SnapshotApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> SnapshotApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> SnapshotApiClient<C> {
        SnapshotApiClient {
            configuration: configuration,
        }
    }
}

pub trait SnapshotApi {
    fn create_snapshot_alias(
        &self,
        snapshot_alias: crate::models::SnapshotAliasCreateParams,
    ) -> Result<crate::models::CreateSnapshotAliasResponse, Error>;
    fn create_snapshot_changelist(
        &self,
        snapshot_changelist: crate::models::SnapshotChangelists,
    ) -> Result<crate::models::CreateSnapshotChangelistResponse, Error>;
    fn create_snapshot_repstate(
        &self,
        snapshot_repstate: crate::models::SnapshotRepstates,
    ) -> Result<crate::models::CreateSnapshotRepstateResponse, Error>;
    fn create_snapshot_schedule(
        &self,
        snapshot_schedule: crate::models::SnapshotScheduleCreateParams,
    ) -> Result<crate::models::CreateSnapshotScheduleResponse, Error>;
    fn create_snapshot_snapshot(
        &self,
        snapshot_snapshot: crate::models::SnapshotSnapshotCreateParams,
    ) -> Result<crate::models::SnapshotSnapshotExtended, Error>;
    fn delete_snapshot_alias(
        &self,
        snapshot_alias_id: &str,
    ) -> Result<(), Error>;
    fn delete_snapshot_aliases(&self) -> Result<(), Error>;
    fn delete_snapshot_changelist(
        &self,
        snapshot_changelist_id: &str,
    ) -> Result<(), Error>;
    fn delete_snapshot_repstate(
        &self,
        snapshot_repstate_id: &str,
    ) -> Result<(), Error>;
    fn delete_snapshot_schedule(
        &self,
        snapshot_schedule_id: &str,
    ) -> Result<(), Error>;
    fn delete_snapshot_schedules(&self) -> Result<(), Error>;
    fn delete_snapshot_snapshot(
        &self,
        snapshot_snapshot_id: &str,
    ) -> Result<(), Error>;
    fn delete_snapshot_snapshots(
        &self,
        _type: &str,
        schedule: &str,
    ) -> Result<(), Error>;
    fn get_snapshot_alias(
        &self,
        snapshot_alias_id: &str,
    ) -> Result<crate::models::SnapshotAliases, Error>;
    fn get_snapshot_changelist(
        &self,
        snapshot_changelist_id: &str,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotChangelists, Error>;
    fn get_snapshot_license(
        &self,
    ) -> Result<crate::models::LicenseLicense, Error>;
    fn get_snapshot_pending(
        &self,
        limit: i32,
        begin: i32,
        schedule: &str,
        end: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotPending, Error>;
    fn get_snapshot_repstate(
        &self,
        snapshot_repstate_id: &str,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotRepstates, Error>;
    fn get_snapshot_schedule(
        &self,
        snapshot_schedule_id: &str,
    ) -> Result<crate::models::SnapshotSchedules, Error>;
    fn get_snapshot_settings(
        &self,
    ) -> Result<crate::models::SnapshotSettings, Error>;
    fn get_snapshot_snapshot(
        &self,
        snapshot_snapshot_id: &str,
    ) -> Result<crate::models::SnapshotSnapshots, Error>;
    fn get_snapshot_snapshots_summary(
        &self,
    ) -> Result<crate::models::SnapshotSnapshotsSummary, Error>;
    fn list_snapshot_aliases(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::SnapshotAliasesExtended, Error>;
    fn list_snapshot_changelists(
        &self,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotChangelistsExtended, Error>;
    fn list_snapshot_repstates(
        &self,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotRepstatesExtended, Error>;
    fn list_snapshot_schedules(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::SnapshotSchedulesExtended, Error>;
    fn list_snapshot_snapshots(
        &self,
        sort: &str,
        schedule: &str,
        resume: &str,
        state: &str,
        limit: i32,
        _type: &str,
        dir: &str,
    ) -> Result<crate::models::SnapshotSnapshotsExtended, Error>;
    fn update_snapshot_alias(
        &self,
        snapshot_alias: crate::models::SnapshotAlias,
        snapshot_alias_id: &str,
    ) -> Result<(), Error>;
    fn update_snapshot_schedule(
        &self,
        snapshot_schedule: crate::models::SnapshotSchedule,
        snapshot_schedule_id: &str,
    ) -> Result<(), Error>;
    fn update_snapshot_settings(
        &self,
        snapshot_settings: crate::models::SnapshotSettingsExtended,
    ) -> Result<(), Error>;
    fn update_snapshot_snapshot(
        &self,
        snapshot_snapshot: crate::models::SnapshotSnapshot,
        snapshot_snapshot_id: &str,
    ) -> Result<(), Error>;
}

impl<C: hyper::client::connect::Connect + 'static + std::marker::Sync + std::marker::Send + Clone> SnapshotApi for SnapshotApiClient<C> {
    fn create_snapshot_alias(
        &self,
        snapshot_alias: crate::models::SnapshotAliasCreateParams,
    ) -> Result<crate::models::CreateSnapshotAliasResponse, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/aliases",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &snapshot_alias,
            hyper::Method::POST,
        )
    }

    fn create_snapshot_changelist(
        &self,
        snapshot_changelist: crate::models::SnapshotChangelists,
    ) -> Result<crate::models::CreateSnapshotChangelistResponse, Error>
    {
        let uri_str = format!(
            "{}/platform/1/snapshot/changelists",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &snapshot_changelist,
            hyper::Method::POST,
        )
    }

    fn create_snapshot_repstate(
        &self,
        snapshot_repstate: crate::models::SnapshotRepstates,
    ) -> Result<crate::models::CreateSnapshotRepstateResponse, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/repstates",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &snapshot_repstate,
            hyper::Method::POST,
        )
    }

    fn create_snapshot_schedule(
        &self,
        snapshot_schedule: crate::models::SnapshotScheduleCreateParams,
    ) -> Result<crate::models::CreateSnapshotScheduleResponse, Error> {
        let uri_str = format!(
            "{}/platform/3/snapshot/schedules",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &snapshot_schedule,
            hyper::Method::POST,
        )
    }

    fn create_snapshot_snapshot(
        &self,
        snapshot_snapshot: crate::models::SnapshotSnapshotCreateParams,
    ) -> Result<crate::models::SnapshotSnapshotExtended, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &snapshot_snapshot,
            hyper::Method::POST,
        )
    }

    fn delete_snapshot_alias(
        &self,
        snapshot_alias_id: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/aliases/{SnapshotAliasId}",
            self.configuration.base_path,
            SnapshotAliasId = snapshot_alias_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_aliases(&self) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/aliases",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_changelist(
        &self,
        snapshot_changelist_id: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/changelists/{SnapshotChangelistId}",
            self.configuration.base_path,
            SnapshotChangelistId = snapshot_changelist_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_repstate(
        &self,
        snapshot_repstate_id: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/repstates/{SnapshotRepstateId}",
            self.configuration.base_path,
            SnapshotRepstateId = snapshot_repstate_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_schedule(
        &self,
        snapshot_schedule_id: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/3/snapshot/schedules/{SnapshotScheduleId}",
            self.configuration.base_path,
            SnapshotScheduleId = snapshot_schedule_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_schedules(&self) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/3/snapshot/schedules",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_snapshot(
        &self,
        snapshot_snapshot_id: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots/{SnapshotSnapshotId}",
            self.configuration.base_path,
            SnapshotSnapshotId = snapshot_snapshot_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_snapshot_snapshots(
        &self,
        _type: &str,
        schedule: &str,
    ) -> Result<(), Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("type", &_type.to_string())
            .append_pair("schedule", &schedule.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_snapshot_alias(
        &self,
        snapshot_alias_id: &str,
    ) -> Result<crate::models::SnapshotAliases, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/aliases/{SnapshotAliasId}",
            self.configuration.base_path,
            SnapshotAliasId = snapshot_alias_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_changelist(
        &self,
        snapshot_changelist_id: &str,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotChangelists, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/changelists/{SnapshotChangelistId}?{}",
            self.configuration.base_path,
            q,
            SnapshotChangelistId = snapshot_changelist_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_license(
        &self,
    ) -> Result<crate::models::LicenseLicense, Error> {
        let uri_str = format!(
            "{}/platform/5/snapshot/license",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_pending(
        &self,
        limit: i32,
        begin: i32,
        schedule: &str,
        end: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotPending, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("begin", &begin.to_string())
            .append_pair("schedule", &schedule.to_string())
            .append_pair("end", &end.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/pending?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_repstate(
        &self,
        snapshot_repstate_id: &str,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotRepstates, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/repstates/{SnapshotRepstateId}?{}",
            self.configuration.base_path,
            q,
            SnapshotRepstateId = snapshot_repstate_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_schedule(
        &self,
        snapshot_schedule_id: &str,
    ) -> Result<crate::models::SnapshotSchedules, Error> {
        let uri_str = format!(
            "{}/platform/3/snapshot/schedules/{SnapshotScheduleId}",
            self.configuration.base_path,
            SnapshotScheduleId = snapshot_schedule_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_settings(
        &self,
    ) -> Result<crate::models::SnapshotSettings, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/settings",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_snapshot(
        &self,
        snapshot_snapshot_id: &str,
    ) -> Result<crate::models::SnapshotSnapshots, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots/{SnapshotSnapshotId}",
            self.configuration.base_path,
            SnapshotSnapshotId = snapshot_snapshot_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_snapshot_snapshots_summary(
        &self,
    ) -> Result<crate::models::SnapshotSnapshotsSummary, Error> {
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots-summary",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_snapshot_aliases(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::SnapshotAliasesExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/aliases?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_snapshot_changelists(
        &self,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotChangelistsExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/changelists?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_snapshot_repstates(
        &self,
        limit: i32,
        resume: &str,
    ) -> Result<crate::models::SnapshotRepstatesExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/repstates?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_snapshot_schedules(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Result<crate::models::SnapshotSchedulesExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/snapshot/schedules?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_snapshot_snapshots(
        &self,
        sort: &str,
        schedule: &str,
        resume: &str,
        state: &str,
        limit: i32,
        _type: &str,
        dir: &str,
    ) -> Result<crate::models::SnapshotSnapshotsExtended, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("schedule", &schedule.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("state", &state.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("type", &_type.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/snapshot/snapshots?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_snapshot_alias(
        &self,
        snapshot_alias: crate::models::SnapshotAlias,
        snapshot_alias_id: &str,
    ) -> Result<(), Error> {
        let uri = format!(
            "{}/platform/1/snapshot/aliases/{SnapshotAliasId}",
            self.configuration.base_path,
            SnapshotAliasId = snapshot_alias_id
        );
        put(self.configuration.borrow(), &uri, &snapshot_alias)
    }

    fn update_snapshot_schedule(
        &self,
        snapshot_schedule: crate::models::SnapshotSchedule,
        snapshot_schedule_id: &str,
    ) -> Result<(), Error> {
        let uri = format!(
            "{}/platform/3/snapshot/schedules/{SnapshotScheduleId}",
            self.configuration.base_path,
            SnapshotScheduleId = snapshot_schedule_id
        );
        put(self.configuration.borrow(), &uri, &snapshot_schedule)
    }

    fn update_snapshot_settings(
        &self,
        snapshot_settings: crate::models::SnapshotSettingsExtended,
    ) -> Result<(), Error> {
        let uri = format!(
            "{}/platform/1/snapshot/settings",
            self.configuration.base_path
        );
        put(self.configuration.borrow(), &uri, &snapshot_settings)
    }

    fn update_snapshot_snapshot(
        &self,
        snapshot_snapshot: crate::models::SnapshotSnapshot,
        snapshot_snapshot_id: &str,
    ) -> Result<(), Error> {
        let uri = format!(
            "{}/platform/1/snapshot/snapshots/{SnapshotSnapshotId}",
            self.configuration.base_path,
            SnapshotSnapshotId = snapshot_snapshot_id
        );
        put(self.configuration.borrow(), &uri, &snapshot_snapshot)
    }
}
