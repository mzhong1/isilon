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

pub struct QuotaQuotasApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> QuotaQuotasApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> QuotaQuotasApiClient<C> {
        QuotaQuotasApiClient {
            configuration: configuration,
        }
    }
}

pub trait QuotaQuotasApi {
    fn create_quota_notification(
        &self,
        quota_notification: crate::models::QuotaNotificationCreateParams,
        qid: &str,
    ) -> Result<crate::models::CreateResponse, Error>;
    fn delete_quota_notification(
        &self,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<(), Error>;
    fn delete_quota_notifications(&self, qid: &str) -> Result<(), Error>;
    fn get_quota_notification(
        &self,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<crate::models::QuotaNotifications, Error>;
    fn list_quota_notifications(
        &self,
        qid: &str,
    ) -> Result<crate::models::QuotaNotificationsExtended, Error>;
    fn update_quota_notification(
        &self,
        quota_notification: crate::models::QuotaNotification,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<(), Error>;
    fn update_quota_notifications(
        &self,
        quota_notifications: crate::models::Empty,
        qid: &str,
    ) -> Result<(), Error>;
}

impl<C: hyper::client::connect::Connect + 'static + std::marker::Sync + std::marker::Send + Clone> QuotaQuotasApi for QuotaQuotasApiClient<C> {
    fn create_quota_notification(
        &self,
        quota_notification: crate::models::QuotaNotificationCreateParams,
        qid: &str,
    ) -> Result<crate::models::CreateResponse, Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications",
            self.configuration.base_path,
            Qid = qid
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &quota_notification,
            hyper::Method::POST,
        )
    }

    fn delete_quota_notification(
        &self,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications/{QuotaNotificationId}",
            self.configuration.base_path,
            QuotaNotificationId = quota_notification_id,
            Qid = qid
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_quota_notifications(&self, qid: &str) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications",
            self.configuration.base_path,
            Qid = qid
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_quota_notification(
        &self,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<crate::models::QuotaNotifications, Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications/{QuotaNotificationId}",
            self.configuration.base_path,
            QuotaNotificationId = quota_notification_id,
            Qid = qid
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_quota_notifications(
        &self,
        qid: &str,
    ) -> Result<crate::models::QuotaNotificationsExtended, Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications",
            self.configuration.base_path,
            Qid = qid
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_quota_notification(
        &self,
        quota_notification: crate::models::QuotaNotification,
        quota_notification_id: &str,
        qid: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications/{QuotaNotificationId}",
            self.configuration.base_path,
            QuotaNotificationId = quota_notification_id,
            Qid = qid
        );
        put(self.configuration.borrow(), &uri_str, &quota_notification)
    }

    fn update_quota_notifications(
        &self,
        quota_notifications: crate::models::Empty,
        qid: &str,
    ) -> Result<(), Error> {
        let uri_str = format!(
            "{}/platform/1/quota/quotas/{Qid}/notifications",
            self.configuration.base_path,
            Qid = qid
        );
        put(self.configuration.borrow(), &uri_str, &quota_notifications)
    }
}
