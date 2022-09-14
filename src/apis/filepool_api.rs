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

pub struct FilepoolApiClient<C: hyper::client::connect::Connect> {
    configuration: Rc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> FilepoolApiClient<C> {
    pub fn new(configuration: Rc<configuration::Configuration<C>>) -> FilepoolApiClient<C> {
        FilepoolApiClient {
            configuration: configuration,
        }
    }
}

pub trait FilepoolApi {
    fn create_filepool_policy(
        &self,
        filepool_policy: crate::models::FilepoolPolicyCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateFilepoolPolicyResponse, Error>>>;
    fn delete_filepool_policy(
        &self,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn get_filepool_default_policy(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolDefaultPolicy, Error>>>;
    fn get_filepool_policy(
        &self,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolPolicies, Error>>>;
    fn get_filepool_template(
        &self,
        filepool_template_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolTemplates, Error>>>;
    fn get_filepool_templates(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolTemplates, Error>>>;
    fn list_filepool_policies(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolPoliciesExtended, Error>>>;
    fn update_filepool_default_policy(
        &self,
        filepool_default_policy: crate::models::FilepoolDefaultPolicyExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
    fn update_filepool_policy(
        &self,
        filepool_policy: crate::models::FilepoolPolicy,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>>;
}

impl<C: hyper::client::connect::Connect + 'static> FilepoolApi for FilepoolApiClient<C> {
    fn create_filepool_policy(
        &self,
        filepool_policy: crate::models::FilepoolPolicyCreateParams,
    ) -> Box<dyn Future<Output = Result<crate::models::CreateFilepoolPolicyResponse, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/policies",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &filepool_policy,
            hyper::Method::GET,
        )
    }

    fn delete_filepool_policy(
        &self,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/policies/{FilepoolPolicyId}",
            self.configuration.base_path,
            FilepoolPolicyId = filepool_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_filepool_default_policy(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolDefaultPolicy, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/default-policy",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_filepool_policy(
        &self,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolPolicies, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/policies/{FilepoolPolicyId}",
            self.configuration.base_path,
            FilepoolPolicyId = filepool_policy_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_filepool_template(
        &self,
        filepool_template_id: &str,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolTemplates, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/templates/{FilepoolTemplateId}",
            self.configuration.base_path,
            FilepoolTemplateId = filepool_template_id
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn get_filepool_templates(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolTemplates, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/templates",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn list_filepool_policies(
        &self,
    ) -> Box<dyn Future<Output = Result<crate::models::FilepoolPoliciesExtended, Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/policies",
            self.configuration.base_path
        );
        query(
            self.configuration.borrow(),
            &uri_str,
            &"",
            hyper::Method::GET,
        )
    }

    fn update_filepool_default_policy(
        &self,
        filepool_default_policy: crate::models::FilepoolDefaultPolicyExtended,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/default-policy",
            self.configuration.base_path
        );
        put(
            self.configuration.borrow(),
            &uri_str,
            &filepool_default_policy,
        )
    }

    fn update_filepool_policy(
        &self,
        filepool_policy: crate::models::FilepoolPolicy,
        filepool_policy_id: &str,
    ) -> Box<dyn Future<Output = Result<(), Error>>> {
        let uri_str = format!(
            "{}/platform/4/filepool/policies/{FilepoolPolicyId}",
            self.configuration.base_path,
            FilepoolPolicyId = filepool_policy_id
        );
        put(self.configuration.borrow(), &uri_str, &filepool_policy)
    }
}
