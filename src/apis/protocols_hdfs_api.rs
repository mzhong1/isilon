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

pub struct ProtocolsHdfsApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> ProtocolsHdfsApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> ProtocolsHdfsApiClient<C> {
        ProtocolsHdfsApiClient {
            configuration: configuration,
        }
    }
}

pub trait ProtocolsHdfsApi {
    fn create_proxyusers_name_member(
        &self,
        proxyusers_name_member: crate::models::AuthAccessAccessItemFileGroup,
        name: &str,
        zone: &str,
    ) -> Result<crate::models::Empty, Error>;
    fn delete_proxyusers_name_member(
        &self,
        proxyusers_name_member_id: &str,
        name: &str,
        zone: &str,
    ) -> Result<(), Error>;
    fn list_proxyusers_name_members(
        &self,
        name: &str,
        zone: &str,
    ) -> Result<crate::models::GroupMembers, Error>;
    fn update_proxyusers_name_member(
        &self,
        proxyusers_name_member: crate::models::Empty,
        proxyusers_name_member_id: &str,
        name: &str,
        zone: &str,
    ) -> Result<(), Error>;
}

impl<C: hyper::client::connect::Connect + 'static + std::marker::Sync + std::marker::Send + Clone> ProtocolsHdfsApi for ProtocolsHdfsApiClient<C> {
    fn create_proxyusers_name_member(
        &self,
        proxyusers_name_member: crate::models::AuthAccessAccessItemFileGroup,
        name: &str,
        zone: &str,
    ) -> Result<crate::models::Empty, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/protocols/hdfs/proxyusers/{Name}/members?{}",
            self.configuration.base_path,
            q,
            Name = name
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &proxyusers_name_member,
            hyper::Method::POST,
        )
    }

    fn delete_proxyusers_name_member(
        &self,
        proxyusers_name_member_id: &str,
        name: &str,
        zone: &str,
    ) -> Result<(), Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/protocols/hdfs/proxyusers/{Name}/members/{ProxyusersNameMemberId}?{}",
            self.configuration.base_path,
            q,
            ProxyusersNameMemberId = proxyusers_name_member_id,
            Name = name
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn list_proxyusers_name_members(
        &self,
        name: &str,
        zone: &str,
    ) -> Result<crate::models::GroupMembers, Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/protocols/hdfs/proxyusers/{Name}/members?{}",
            self.configuration.base_path,
            q,
            Name = name
        );

        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_proxyusers_name_member(
        &self,
        proxyusers_name_member: crate::models::Empty,
        proxyusers_name_member_id: &str,
        name: &str,
        zone: &str,
    ) -> Result<(), Error> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("zone", &zone.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/1/protocols/hdfs/proxyusers/{Name}/members/{ProxyusersNameMemberId}?{}",
            self.configuration.base_path,
            q,
            ProxyusersNameMemberId = proxyusers_name_member_id,
            Name = name
        );

        put(
            self.configuration.borrow(),
            &uri_str,
            &proxyusers_name_member,
        )
    }
}
