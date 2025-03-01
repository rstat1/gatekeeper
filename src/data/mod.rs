/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use serde::{Deserialize, Serialize};

use mongodb::bson::doc;
use mongodb::sync::{Client, Collection};

pub struct DataStore {
    collectionName: String,
    pub client: Client,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SystemConfiguration {
    #[serde(rename = "vaultAddr")]
    pub vaultEndpoint: String,
    #[serde(rename = "dbAddr")]
    pub mongoEndpoint: String,
    #[serde(rename = "dbName")]
    pub collectionName: String,
    #[serde(rename = "redisAddr")]
    pub redisServerAddress: String,
}

/// A ServiceDomain is used to assign services to a base domain.
///
/// Each assigned service inherits the security policies applied to the base domain.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceDomain {
    pub base: String,
    pub services: Vec<String>,
    pub frostCompatEnabled: bool,
    pub securityPolicies: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub internal: bool,
    pub securityPolices: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: i16,
    pub listeningAddress: String,
}

impl DataStore {
    pub fn new(username: &String, password: &String, epAddr: &String, collection: String) -> Result<Self, mongodb::error::Error> {
        let mongoEP = format!("mongodb://{}:{}@{}/{}?directconnection=true&appName=gatekeeper", username, password, epAddr, collection);

        let c = Client::with_uri_str(mongoEP.clone());
        match c {
            Ok(c) => Ok(DataStore { client: c, collectionName: collection }),
            Err(e) => Err(e),
        }
    }
    pub fn GetDomain(&self, _name: String) -> ServiceDomain {
        ServiceDomain { base: "".to_string(), services: Vec::new(), securityPolicies: None, frostCompatEnabled: false }
    }
    pub fn GetDomainNames(&self) -> Result<Vec<String>, mongodb::error::Error> {
        let servicesColl: Collection<ServiceDomain> = self.client.database(&self.collectionName).collection("servicedomains");

        let cursor = servicesColl.find(doc! {}).run()?;

        let mut domains: Vec<String> = Vec::new();

        for domain in cursor {
            let d = domain?;
            domains.push(d.base);
        }
        Ok(domains)
    }
}
