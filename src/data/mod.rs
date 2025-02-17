/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use mongodb::Client;
use serde::{Deserialize, Serialize};

pub struct DataStore {
    pub client: mongodb::Client,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SystemConfiguration {
    #[serde(rename = "vaultAddr")]
    pub vault_endpoint: String,
    #[serde(rename = "dbAddr")]
    pub mongo_endpoint: String,
    #[serde(rename = "dbName")]
    pub collection_name: String,
}

/// A ServiceDomain is used to assign services to a base domain.
///
/// Each assigned service inherits the security policies applied to the base domain.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceDomain {
    pub base: String,
    pub services: Option<Vec<String>>,
    pub applied_policies: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub internal: bool,
}

impl DataStore {
    pub async fn new(mongo_ep: &String) -> Result<Self, String> {
        let c = Client::with_uri_str(mongo_ep).await;
        match c {
            Ok(c) => Ok(DataStore { client: c }),
            Err(e) => Err(format!("Error connecting to mongo: {e}")),
        }
    }
    pub fn get_domain(&self, _name: String) -> ServiceDomain {
        ServiceDomain { base: "".to_string(), services: None, applied_policies: None }
    }
}
