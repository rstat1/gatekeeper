/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use futures::stream::{StreamExt, TryStreamExt};
use mongodb::bson::{doc, Document};
use mongodb::{Client, ClientSession, Collection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    #[serde(rename = "listenOnTLS")]
    pub tlsListenerAddr: String,
    #[serde(rename = "listenOn")]
    pub listenerAddr: String,
}

/// A ServiceDomain is used to assign services to a base domain.
///
/// Each assigned service inherits the security policies applied to the base domain.
#[derive(Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: String,
    pub base: String,
    pub services: Vec<String>,
    pub frostCompatEnabled: bool,
    pub securityPolicies: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GatekeeperService {
    pub id: String,
    pub name: String,
    pub internal: bool,
    pub isFrostSvc: bool,
    pub healthCheckRoute: String,
    pub securityPolices: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: i16,
    pub listeningAddress: String,
}

impl DataStore {
    pub async fn new(username: &String, password: &String, epAddr: &String, collection: String) -> Result<Arc<Self>, mongodb::error::Error> {
        let mongoEP = format!(
            "mongodb://{}:{}@{}/{}?directconnection=true&appName=gatekeeper&retryWrites=false",
            username, password, epAddr, collection
        );

        let c = Client::with_uri_str(mongoEP.clone()).await;
        match c {
            Ok(c) => Ok(Arc::new(DataStore {
                client: c,
                collectionName: collection,
            })),
            Err(e) => Err(e),
        }
    }
    pub async fn GetDomain(&self, name: &String) -> Result<Option<Domain>, mongodb::error::Error> {
        let coll: Collection<Domain> = self.client.database(&self.collectionName).collection::<Domain>("servicedomains");
        let cursor = coll.find_one(doc! {"base": name}).await;
        match cursor {
            Ok(Some(sd)) => Ok(Some(sd)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub async fn GetDomainNames(&self) -> Result<Vec<String>, mongodb::error::Error> {
        let serviceDomainsColl: Collection<Domain> = self.client.database(&self.collectionName).collection("servicedomains");
        let cursor = serviceDomainsColl.find(doc! {}).await; //.run()?;
        let mut domains: Vec<String> = Vec::new();

        match cursor {
            Ok(mut c) => {
                while let Some(doc) = c.try_next().await? {
                    domains.push(doc.base);
                }
                Ok(domains)
            }
            Err(e) => Err(e),
        }
    }
    pub async fn GetDomains(&self) -> Result<Vec<Domain>, mongodb::error::Error> {
        let serviceDomainsColl: Collection<Domain> = self.client.database(&self.collectionName).collection("servicedomains");
        let cursor = serviceDomainsColl.find(doc! {}).await; //.run()?;
        let mut domains: Vec<Domain> = Vec::new();

        match cursor {
            Ok(mut c) => {
                while let Some(doc) = c.try_next().await? {
                    domains.push(doc);
                }
                Ok(domains)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn NewServiceDomain(&self, domain: &Domain) -> Result<bool, mongodb::error::Error> {
        self.insertUnique("servicedomains", domain, doc! {"base": &domain.base}, None).await
    }
    pub async fn NewService(&self, svc: &GatekeeperService, parentDomain: &String) -> Result<bool, mongodb::error::Error> {
        let mut newSvcSession = self.client.start_session().await.unwrap();

        newSvcSession.start_transaction().await;
        match self.insertUnique("services", svc, doc! {"name": &svc.name}, Some(&mut newSvcSession)).await {
            Ok(r) => {
                if r {
                    self.AddServiceToDomain(&svc.name, parentDomain, &mut newSvcSession).await
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                newSvcSession.abort_transaction().await;
                Err(e)
            }
        }
    }
    async fn AddServiceToDomain(&self, serviceName: &String, domainName: &String, session: &mut ClientSession) -> Result<bool, mongodb::error::Error> {
        let coll: Collection<Domain> = self.client.database(&self.collectionName).collection::<Domain>("servicedomains");

        match coll
            .update_one(doc! {"base": domainName}, doc! {"$addToSet": doc!{"services": doc!{"$each": [serviceName]}}})
            .session(&mut *session)
            .await
        {
            Ok(r) => {
                if r.modified_count > 0 {
                    session.commit_transaction().await;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(e),
        }
    }
    async fn insertUnique<T>(&self, collName: &str, doc: &T, criteriaForUnique: Document, session: Option<&mut ClientSession>) -> Result<bool, mongodb::error::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync + Clone,
    {
        let coll: Collection<T> = self.client.database(&self.collectionName).collection::<T>(collName);
        let cursor: Result<Option<T>, mongodb::error::Error>;
        if let Some(session) = session {
            cursor = coll.find_one(criteriaForUnique).session(session).await;
        } else {
            cursor = coll.find_one(criteriaForUnique).await;
        }
        match cursor {
            Ok(Some(_)) => Ok(false),
            Ok(None) => match coll.insert_one(doc).await {
                Ok(_) => Ok(true),
                Err(err) => Err(err),
            },
            Err(e) => Err(e),
        }
    }
}
