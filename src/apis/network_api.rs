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

pub struct NetworkApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> NetworkApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> NetworkApiClient<C> {
        NetworkApiClient {
            configuration: configuration,
        }
    }
}

pub trait NetworkApi {
    fn create_dnscache_flush_item(
        &self,
        dnscache_flush_item: crate::models::Empty,
    ) -> Box<dyn Future<Item = crate::models::Empty, Error = Error>>;
    fn create_network_groupnet(
        &self,
        network_groupnet: crate::models::NetworkGroupnetCreateParams,
    ) -> Box<dyn Future<Item = crate::models::CreateResponse, Error = Error>>;
    fn create_network_sc_rebalance_all_item(
        &self,
        network_sc_rebalance_all_item: crate::models::Empty,
    ) -> Box<dyn Future<Item = crate::models::Empty, Error = Error>>;
    fn delete_network_groupnet(
        &self,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn get_network_dnscache(
        &self,
    ) -> Box<dyn Future<Item = crate::models::NetworkDnscache, Error = Error>>;
    fn get_network_external(
        &self,
    ) -> Box<dyn Future<Item = crate::models::NetworkExternal, Error = Error>>;
    fn get_network_groupnet(
        &self,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkGroupnets, Error = Error>>;
    fn get_network_interfaces(
        &self,
        sort: &str,
        network: &str,
        resume: &str,
        lnns: &str,
        alloc_method: &str,
        limit: i32,
        dir: &str,
    ) -> Box<dyn Future<Item = crate::models::PoolsPoolInterfaces, Error = Error>>;
    fn get_network_pools(
        &self,
        sort: &str,
        subnet: &str,
        resume: &str,
        access_zone: &str,
        alloc_method: &str,
        limit: i32,
        groupnet: &str,
        dir: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkPools, Error = Error>>;
    fn get_network_rules(
        &self,
        sort: &str,
        subnet: &str,
        resume: &str,
        limit: i32,
        dir: &str,
        groupnet: &str,
        pool: &str,
    ) -> Box<dyn Future<Item = crate::models::PoolsPoolRulesExtended, Error = Error>>;
    fn get_network_subnets(
        &self,
        sort: &str,
        groupnet: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Item = crate::models::GroupnetSubnetsExtended, Error = Error>>;
    fn list_network_groupnets(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkGroupnetsExtended, Error = Error>>;
    fn update_network_dnscache(
        &self,
        network_dnscache: crate::models::NetworkDnscacheExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_network_external(
        &self,
        network_external: crate::models::NetworkExternalExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_network_groupnet(
        &self,
        network_groupnet: crate::models::NetworkGroupnet,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
}

impl<C: hyper::client::connect::Connect + 'static> NetworkApi for NetworkApiClient<C> {
    fn create_dnscache_flush_item(
        &self,
        dnscache_flush_item: crate::models::Empty,
    ) -> Box<dyn Future<Item = crate::models::Empty, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/dnscache/flush",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &dnscache_flush_item,
            hyper::Method::POST,
        )
    }

    fn create_network_groupnet(
        &self,
        network_groupnet: crate::models::NetworkGroupnetCreateParams,
    ) -> Box<dyn Future<Item = crate::models::CreateResponse, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/groupnets",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &network_groupnet,
            hyper::Method::POST,
        )
    }

    fn create_network_sc_rebalance_all_item(
        &self,
        network_sc_rebalance_all_item: crate::models::Empty,
    ) -> Box<dyn Future<Item = crate::models::Empty, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/sc-rebalance-all",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &network_sc_rebalance_all_item,
            hyper::Method::POST,
        )
    }

    fn delete_network_groupnet(
        &self,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/network/groupnets/{NetworkGroupnetId}",
            self.configuration.base_path,
            NetworkGroupnetId = network_groupnet_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::DELETE,
        )
    }

    fn get_network_dnscache(
        &self,
    ) -> Box<dyn Future<Item = crate::models::NetworkDnscache, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/dnscache",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_external(
        &self,
    ) -> Box<dyn Future<Item = crate::models::NetworkExternal, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/external",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_groupnet(
        &self,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkGroupnets, Error = Error>> {
        let uri_str = format!(
            "{}/platform/3/network/groupnets/{NetworkGroupnetId}",
            self.configuration.base_path,
            NetworkGroupnetId = network_groupnet_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_interfaces(
        &self,
        sort: &str,
        network: &str,
        resume: &str,
        lnns: &str,
        alloc_method: &str,
        limit: i32,
        dir: &str,
    ) -> Box<dyn Future<Item = crate::models::PoolsPoolInterfaces, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("network", &network.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("lnns", &lnns.to_string())
            .append_pair("alloc_method", &alloc_method.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/network/interfaces?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_pools(
        &self,
        sort: &str,
        subnet: &str,
        resume: &str,
        access_zone: &str,
        alloc_method: &str,
        limit: i32,
        groupnet: &str,
        dir: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkPools, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("subnet", &subnet.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("access_zone", &access_zone.to_string())
            .append_pair("alloc_method", &alloc_method.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("groupnet", &groupnet.to_string())
            .append_pair("dir", &dir.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/network/pools?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_rules(
        &self,
        sort: &str,
        subnet: &str,
        resume: &str,
        limit: i32,
        dir: &str,
        groupnet: &str,
        pool: &str,
    ) -> Box<dyn Future<Item = crate::models::PoolsPoolRulesExtended, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("subnet", &subnet.to_string())
            .append_pair("resume", &resume.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("groupnet", &groupnet.to_string())
            .append_pair("pool", &pool.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/network/rules?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_network_subnets(
        &self,
        sort: &str,
        groupnet: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Item = crate::models::GroupnetSubnetsExtended, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("groupnet", &groupnet.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/4/network/subnets?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_network_groupnets(
        &self,
        sort: &str,
        limit: i32,
        dir: &str,
        resume: &str,
    ) -> Box<dyn Future<Item = crate::models::NetworkGroupnetsExtended, Error = Error>> {
        let q = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sort", &sort.to_string())
            .append_pair("limit", &limit.to_string())
            .append_pair("dir", &dir.to_string())
            .append_pair("resume", &resume.to_string())
            .finish();
        let uri_str = format!(
            "{}/platform/3/network/groupnets?{}",
            self.configuration.base_path, q
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_network_dnscache(
        &self,
        network_dnscache: crate::models::NetworkDnscacheExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/network/dnscache",
            self.configuration.base_path
        );
        put(self.configuration.borrow(), &uri_str, &network_dnscache)
    }

    fn update_network_external(
        &self,
        network_external: crate::models::NetworkExternalExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/network/external",
            self.configuration.base_path
        );
        put(self.configuration.borrow(), &uri_str, &network_external)
    }

    fn update_network_groupnet(
        &self,
        network_groupnet: crate::models::NetworkGroupnet,
        network_groupnet_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/3/network/groupnets/{NetworkGroupnetId}",
            self.configuration.base_path,
            NetworkGroupnetId = network_groupnet_id
        );
        put(self.configuration.borrow(), &uri_str, &network_groupnet)
    }
}
