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

pub struct EventApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> EventApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> EventApiClient<C> {
        EventApiClient {
            configuration: configuration,
        }
    }
}

pub trait EventApi {
    fn create_event_alert_condition(
        &self,
        event_alert_condition: crate::models::EventAlertConditionCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn create_event_channel(
        &self,
        event_channel: crate::models::EventChannelCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>>;
    fn create_event_event(
        &self,
        event_event: crate::models::EventEvent,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateQuotaReportResponse, Error>>>;
    fn delete_event_alert_condition(
        &self,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_event_alert_conditions(
        &self,
        channel: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn delete_event_channel(
        &self,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn get_event_alert_condition(
        &self,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventAlertConditions, Error>>>;
    fn get_event_categories(
        &self,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventCategoriesExtended, Error>>>;
    fn get_event_category(
        &self,
        event_category_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventCategories, Error>>>;
    fn get_event_channel(
        &self,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventChannels, Error>>>;
    fn get_event_eventgroup_definition(
        &self,
        event_eventgroup_definition_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupDefinitions, Error>>>;
    fn get_event_eventgroup_definitions(
        &self,
        category: i32,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupDefinitionsExtended, Error>>>;
    fn get_event_eventgroup_occurrence(
        &self,
        event_eventgroup_occurrence_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupOccurrences, Error>>>;
    fn get_event_eventgroup_occurrences(
        &self,
        resolved: bool,
        sort: &str,
        begin: i32,
        end: i32,
        event_count: i32,
        resume: &str,
        ignore: bool,
        limit: i32,
        resolver: &str,
        cause: &str,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupOccurrencesExtended, Error>>>;
    fn get_event_eventlist(
        &self,
        event_eventlist_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventlists, Error>>>;
    fn get_event_eventlists(
        &self,
        event_instance: &str,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventlistsExtended, Error>>>;
    fn get_event_settings(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::EventSettings, Error>>>;
    fn list_event_alert_conditions(
        &self,
        channels: &str,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventAlertConditionsExtended, Error>>>;
    fn list_event_channels(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventChannelsExtended, Error>>>;
    fn update_event_alert_condition(
        &self,
        event_alert_condition: crate::models::EventAlertCondition,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_event_channel(
        &self,
        event_channel: crate::models::EventChannel,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_event_eventgroup_occurrence(
        &self,
        event_eventgroup_occurrence: crate::models::EventEventgroupOccurrence,
        event_eventgroup_occurrence_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_event_eventgroup_occurrences(
        &self,
        event_eventgroup_occurrences: crate::models::EventEventgroupOccurrence,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_event_settings(
        &self,
        event_settings: crate::models::EventSettings,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
}

impl<C: hyper::client::connect::Connect + 'static> EventApi for EventApiClient<C> {
    fn create_event_alert_condition(
        &self,
        event_alert_condition: crate::models::EventAlertConditionCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &event_alert_condition,
            hyper::Method::POST,
        )
    }

    fn create_event_channel(
        &self,
        event_channel: crate::models::EventChannelCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateResponse, Error>>> {
        let uri_str = format!("{}/platform/3/event/channels", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &event_channel,
            hyper::Method::POST,
        )
    }

    fn create_event_event(
        &self,
        event_event: crate::models::EventEvent,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateQuotaReportResponse, Error>>> {
        let uri_str = format!("{}/platform/3/event/events", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &event_event,
            hyper::Method::POST,
        )
    }

    fn delete_event_alert_condition(
        &self,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions/{EventAlertConditionId}",
            self.configuration.base_path,
            EventAlertConditionId = event_alert_condition_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_event_alert_conditions(
        &self,
        channel: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("channel", &channel.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn delete_event_channel(
        &self,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/channels/{EventChannelId}",
            self.configuration.base_path,
            EventChannelId = event_channel_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_event_alert_condition(
        &self,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventAlertConditions, Error>>> {
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions/{EventAlertConditionId}",
            self.configuration.base_path,
            EventAlertConditionId = event_alert_condition_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_categories(
        &self,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventCategoriesExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/event/categories?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_category(
        &self,
        event_category_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventCategories, Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/categories/{EventCategoryId}",
            self.configuration.base_path,
            EventCategoryId = event_category_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_channel(
        &self,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventChannels, Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/channels/{EventChannelId}",
            self.configuration.base_path,
            EventChannelId = event_channel_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventgroup_definition(
        &self,
        event_eventgroup_definition_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupDefinitions, Error>>> {
        let uri_str = format!(
            "{}/platform/4/event/eventgroup-definitions/{EventEventgroupDefinitionId}",
            self.configuration.base_path,
            EventEventgroupDefinitionId = event_eventgroup_definition_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventgroup_definitions(
        &self,
        category: i32,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupDefinitionsExtended, Error>>>
    {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("category", &category.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/event/eventgroup-definitions?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventgroup_occurrence(
        &self,
        event_eventgroup_occurrence_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupOccurrences, Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/eventgroup-occurrences/{EventEventgroupOccurrenceId}",
            self.configuration.base_path,
            EventEventgroupOccurrenceId = event_eventgroup_occurrence_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventgroup_occurrences(
        &self,
        resolved: bool,
        sort: &str,
        begin: i32,
        end: i32,
        event_count: i32,
        resume: &str,
        ignore: bool,
        limit: i32,
        resolver: &str,
        cause: &str,
        dir: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventgroupOccurrencesExtended, Error>>>
    {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("resolved", &resolved.to_string())
            .append_pair("sort", &sort.to_string())
            .append_pair("begin", &begin.to_string())
            .append_pair("end", &end.to_string())
            .append_pair("event_count", &event_count.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("ignore", &ignore.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("resolver", &resolver.to_string())
            .append_pair("cause", &cause.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/event/eventgroup-occurrences?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventlist(
        &self,
        event_eventlist_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventlists, Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/eventlists/{EventEventlistId}",
            self.configuration.base_path,
            EventEventlistId = event_eventlist_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_eventlists(
        &self,
        event_instance: &str,
        limit: i32,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventEventlistsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("event_instance", &event_instance.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/event/eventlists?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_event_settings(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::EventSettings, Error>>> {
        let uri_str = format!("{}/platform/3/event/settings", self.configuration.base_path);
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_event_alert_conditions(
        &self,
        channels: &str,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventAlertConditionsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("channels", &channels.to_string())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_event_channels(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::EventChannelsExtended, Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/event/channels?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_event_alert_condition(
        &self,
        event_alert_condition: crate::models::EventAlertCondition,
        event_alert_condition_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/4/event/alert-conditions/{EventAlertConditionId}",
            self.configuration.base_path,
            EventAlertConditionId = event_alert_condition_id
        );
        put(
            self.configuration.borrow(),
            &uri_str,
            &event_alert_condition,
        )
    }

    fn update_event_channel(
        &self,
        event_channel: crate::models::EventChannel,
        event_channel_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/channels/{EventChannelId}",
            self.configuration.base_path,
            EventChannelId = event_channel_id
        );
        put(self.configuration.borrow(), &uri_str, &event_channel)
    }

    fn update_event_eventgroup_occurrence(
        &self,
        event_eventgroup_occurrence: crate::models::EventEventgroupOccurrence,
        event_eventgroup_occurrence_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/eventgroup-occurrences/{EventEventgroupOccurrenceId}",
            self.configuration.base_path,
            EventEventgroupOccurrenceId = event_eventgroup_occurrence_id
        );
        put(
            self.configuration.borrow(),
            &uri_str,
            &event_eventgroup_occurrence,
        )
    }

    fn update_event_eventgroup_occurrences(
        &self,
        event_eventgroup_occurrences: crate::models::EventEventgroupOccurrence,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/event/eventgroup-occurrences",
            self.configuration.base_path
        );
        put(
            self.configuration.borrow(),
            &uri_str,
            &event_eventgroup_occurrences,
        )
    }

    fn update_event_settings(
        &self,
        event_settings: crate::models::EventSettings,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!("{}/platform/3/event/settings", self.configuration.base_path);
        put(self.configuration.borrow(), &uri_str, &event_settings)
    }
}
