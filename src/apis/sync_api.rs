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
pub struct SyncApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}
#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect> SyncApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> SyncApiClient<C> {
        SyncApiClient {
            configuration: configuration,
        }
    }
}

pub trait SyncApi {
    fn create_sync_job(
        &self,
        sync_job: crate::models::SyncJobCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn create_sync_policy(
        &self,
        sync_policy: crate::models::SyncPolicyCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn create_sync_reports_rotate_item(
        &self,
        sync_reports_rotate_item: crate::models::Empty,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateSyncReportsRotateItemResponse, Error>>>;
    fn create_sync_rule(
        &self,
        sync_rule: crate::models::SyncRuleCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn delete_sync_policies(
        &self,
        local_only: bool,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_sync_policy(
        &self,
        sync_policy_id: &str,
        local_only: bool,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_sync_rule(&self, sync_rule_id: &str) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_sync_rules(&self, _type: &str) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_target_policy(
        &self,
        target_policy_id: &str,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn get_history_cpu(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>>;
    fn get_history_file(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>>;
    fn get_history_network(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>>;
    fn get_history_worker(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>>;
    fn get_sync_job(
        &self,
        sync_job_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncJobs, Error>>>;
    fn get_sync_license(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::LicenseLicense, Error>>>;
    fn get_sync_policy(
        &self,
        sync_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncPolicies, Error>>>;
    fn get_sync_report(
        &self,
        sync_report_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReports, Error>>>;
    fn get_sync_reports(
        &self,
        sort: &str,
        resume: &str,
        newer_than: i32,
        policy_name: &str,
        state: &str,
        limit: i32,
        reports_per_policy: i32,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReportsExtended, Error>>>;
    fn get_sync_rule(
        &self,
        sync_rule_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncRules, Error>>>;
    fn get_sync_settings(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncSettings, Error>>>;
    fn get_target_policies(
        &self,
        sort: &str,
        target_path: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetPoliciesExtended, Error>>>;
    fn get_target_policy(
        &self,
        target_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetPolicies, Error>>>;
    fn get_target_report(
        &self,
        target_report_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetReports, Error>>>;
    fn get_target_reports(
        &self,
        sort: &str,
        resume: &str,
        newer_than: i32,
        policy_name: &str,
        state: &str,
        limit: i32,
        reports_per_policy: i32,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetReportsExtended, Error>>>;
    fn list_sync_jobs(
        &self,
        sort: &str,
        state: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncJobsExtended, Error>>>;
    fn list_sync_policies(
        &self,
        sort: &str,
        resume: &str,
        summary: bool,
        limit: i32,
        scope: &str,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncPoliciesExtended, Error>>>;
    fn list_sync_reports_rotate(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReportsRotate, Error>>>;
    fn list_sync_rules(
        &self,
        sort: &str,
        _type: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncRulesExtended, Error>>>;
    fn update_sync_job(
        &self,
        sync_job: crate::models::SyncJob,
        sync_job_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_sync_policy(
        &self,
        sync_policy: crate::models::SyncPolicy,
        sync_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_sync_rule(
        &self,
        sync_rule: crate::models::SyncRule,
        sync_rule_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_sync_settings(
        &self,
        sync_settings: crate::models::SyncSettingsExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
}
#[cfg(feature = "client")]
impl<C: hyper::client::connect::Connect + 'static> SyncApi for SyncApiClient<C> {
    fn create_sync_job(
        &self,
        sync_job: crate::models::SyncJobCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!("{}/platform/3/sync/jobs", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &sync_job,
            hyper::Method::POST,
        )
    }

    fn create_sync_policy(
        &self,
        sync_policy: crate::models::SyncPolicyCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!("{}/platform/3/sync/policies", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &sync_policy,
            hyper::Method::POST,
        )
    }

    fn create_sync_reports_rotate_item(
        &self,
        sync_reports_rotate_item: crate::models::Empty,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateSyncReportsRotateItemResponse, Error>>>
    {
        let uri_str = format!(
            "{}/platform/1/sync/reports-rotate",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &sync_reports_rotate_item,
            hyper::Method::POST,
        )
    }

    fn create_sync_rule(
        &self,
        sync_rule: crate::models::SyncRuleCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!("{}/platform/3/sync/rules", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &sync_rule,
            hyper::Method::POST,
        )
    }

    fn delete_sync_policies(
        &self,
        local_only: bool,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("local_only", &local_only.to_string())
            .append_pair("force", &force.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/policies?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_sync_policy(
        &self,
        sync_policy_id: &str,
        local_only: bool,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("local_only", &local_only.to_string())
            .append_pair("force", &force.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/policies/{SyncPolicyId}?{}",
            self.configuration.base_path,
            q,
            SyncPolicyId = sync_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_sync_rule(&self, sync_rule_id: &str) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/rules/{SyncRuleId}",
            self.configuration.base_path,
            SyncRuleId = sync_rule_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_sync_rules(&self, _type: &str) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("type", &_type.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/rules?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_target_policy(
        &self,
        target_policy_id: &str,
        force: bool,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("force", &force.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/sync/target/policies/{TargetPolicyId}?{}",
            self.configuration.base_path,
            q,
            TargetPolicyId = target_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_history_cpu(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("begin", &begin.to_string())
            .append_pair("end", &end.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/history/cpu?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_history_file(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("begin", &begin.to_string())
            .append_pair("end", &end.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/sync/history/file?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_history_network(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("begin", &begin.to_string())
            .append_pair("end", &end.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/sync/history/network?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_history_worker(
        &self,
        begin: i32,
        end: i32,
    ) -> Box<dyn Future<Output = Result<crate::models::HistoryFile, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("begin", &begin.to_string())
            .append_pair("end", &end.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/history/worker?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_job(
        &self,
        sync_job_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncJobs, Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/jobs/{SyncJobId}",
            self.configuration.base_path,
            SyncJobId = sync_job_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_license(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::LicenseLicense, Error>>> {
        let uri_str = format!("{}/platform/5/sync/license", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_policy(
        &self,
        sync_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncPolicies, Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/policies/{SyncPolicyId}",
            self.configuration.base_path,
            SyncPolicyId = sync_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_report(
        &self,
        sync_report_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReports, Error>>> {
        let uri_str = format!(
            "{}/platform/4/sync/reports/{SyncReportId}",
            self.configuration.base_path,
            SyncReportId = sync_report_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_reports(
        &self,
        sort: &str,
        resume: &str,
        newer_than: i32,
        policy_name: &str,
        state: &str,
        limit: i32,
        reports_per_policy: i32,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReportsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("newer_than", &newer_than.to_string())
            .append_pair("policy_name", &policy_name.to_string())
            .append_pair("state", &state.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("reports_per_policy", &reports_per_policy.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/sync/reports?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_rule(
        &self,
        sync_rule_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncRules, Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/rules/{SyncRuleId}",
            self.configuration.base_path,
            SyncRuleId = sync_rule_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_sync_settings(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncSettings, Error>>> {
        let uri_str = format!("{}/platform/3/sync/settings", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_target_policies(
        &self,
        sort: &str,
        target_path: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetPoliciesExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("target_path", &target_path.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/sync/target/policies?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_target_policy(
        &self,
        target_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetPolicies, Error>>> {
        let uri_str = format!(
            "{}/platform/1/sync/target/policies/{TargetPolicyId}",
            self.configuration.base_path,
            TargetPolicyId = target_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_target_report(
        &self,
        target_report_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetReports, Error>>> {
        let uri_str = format!(
            "{}/platform/4/sync/target/reports/{TargetReportId}",
            self.configuration.base_path,
            TargetReportId = target_report_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_target_reports(
        &self,
        sort: &str,
        resume: &str,
        newer_than: i32,
        policy_name: &str,
        state: &str,
        limit: i32,
        reports_per_policy: i32,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::TargetReportsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("newer_than", &newer_than.to_string())
            .append_pair("policy_name", &policy_name.to_string())
            .append_pair("state", &state.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("reports_per_policy", &reports_per_policy.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/sync/target/reports?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_sync_jobs(
        &self,
        sort: &str,
        state: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncJobsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("state", &state.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/jobs?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_sync_policies(
        &self,
        sort: &str,
        resume: &str,
        summary: bool,
        limit: i32,
        scope: &str,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncPoliciesExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("summary", &summary.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("scope", &scope.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/policies?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_sync_reports_rotate(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncReportsRotate, Error>>> {
        let uri_str = format!(
            "{}/platform/1/sync/reports-rotate",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_sync_rules(
        &self,
        sort: &str,
        _type: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::SyncRulesExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("type", &_type.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/sync/rules?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_sync_job(
        &self,
        sync_job: crate::models::SyncJob,
        sync_job_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/jobs/{SyncJobId}",
            self.configuration.base_path,
            SyncJobId = sync_job_id
        );
        put(self.configuration.borrow(), &uri_str, &sync_job)
    }

    fn update_sync_policy(
        &self,
        sync_policy: crate::models::SyncPolicy,
        sync_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/policies/{SyncPolicyId}",
            self.configuration.base_path,
            SyncPolicyId = sync_policy_id
        );
        put(self.configuration.borrow(), &uri_str, &sync_policy)
    }

    fn update_sync_rule(
        &self,
        sync_rule: crate::models::SyncRule,
        sync_rule_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/sync/rules/{SyncRuleId}",
            self.configuration.base_path,
            SyncRuleId = sync_rule_id
        );
        put(self.configuration.borrow(), &uri_str, &sync_rule)
    }

    fn update_sync_settings(
        &self,
        sync_settings: crate::models::SyncSettingsExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!("{}/platform/3/sync/settings", self.configuration.base_path);
        put(self.configuration.borrow(), &uri_str, &sync_settings)
    }
}
