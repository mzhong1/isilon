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

use super::{configuration, query, Error};
use futures;
use futures::Future;
use hyper;

pub struct AuthGroupsApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> AuthGroupsApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> AuthGroupsApiClient<C> {
        AuthGroupsApiClient {
            configuration: configuration,
        }
    }
}

pub trait AuthGroupsApi {
    fn create_group_member(
        &self,
        group_member: crate::models::AuthAccessAccessItemFileGroup,
        group: &str,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Item = crate::models::CreateResponse, Error = Error>>;
    fn delete_group_member(
        &self,
        group_member_id: &str,
        group: &str,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn list_group_members(
        &self,
        group: &str,
        resolve_names: bool,
        resume: &str,
        limit: i32,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Item = crate::models::GroupMembers, Error = Error>>;
}

impl<C: hyper::client::connect::Connect + 'static> AuthGroupsApi for AuthGroupsApiClient<C> {
    fn create_group_member(
        &self,
        group_member: crate::models::AuthAccessAccessItemFileGroup,
        group: &str,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Item = crate::models::CreateResponse, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .append_pair("provider", &provider.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/auth/groups/{Group}/members?{}",
            self.configuration.base_path,
            q,
            Group = group
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &group_member,
            hyper::Method::POST,
        )
    }

    fn delete_group_member(
        &self,
        group_member_id: &str,
        group: &str,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .append_pair("provider", &provider.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/auth/groups/{Group}/members/{GroupMemberId}?{}",
            self.configuration.base_path,
            q,
            GroupMemberId = group_member_id,
            Group = group
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn list_group_members(
        &self,
        group: &str,
        resolve_names: bool,
        resume: &str,
        limit: i32,
        zone: &str,
        provider: &str,
    ) -> Box<dyn Future<Item = crate::models::GroupMembers, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("resolve_names", &resolve_names.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("zone", &zone.to_string())
            .append_pair("provider", &provider.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/auth/groups/{Group}/members?{}",
            self.configuration.base_path,
            q,
            Group = group
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }
}
