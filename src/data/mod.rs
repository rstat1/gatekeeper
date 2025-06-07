/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use futures::stream::TryStreamExt;
use mongodb::{
	bson::{doc, Document},
	error::ErrorKind,
	Client, ClientSession, Collection,
};
use redis::Commands;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{future::Future, sync::Arc};
use tokio::sync::RwLock;
use tracing::error;

use crate::{
	services::v1::{Alias, Namespace, Service},
	vault::VaultClient,
};

pub struct DataStore {
	mongoClient: RwLock<Client>,
	serverEP: String,
	collectionName: String,
	vault: Arc<VaultClient>,
	pub redis: redis::Client,
	dev: bool,
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
	#[serde(rename = "pingIntervalSecs")]
	pub healthCheckInterval: Option<u64>,
	pub staticFileServerAddr: Option<String>,
	pub devAuthServerAddr: Option<String>,
	pub apiServerAddr: Option<String>,
	pub devMode: Option<bool>,
	pub acmeContactEmail: String,
	pub certCheckInterval: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Endpoint {
	pub port: i16,
	pub listeningAddress: String,
}

impl DataStore {
	pub async fn new(username: &String, password: &String, epAddr: &String, collection: String, vault: Arc<VaultClient>, redisAddr: String, dev: bool) -> Result<Arc<Self>, mongodb::error::Error> {
		let mongoEP = format!(
			"mongodb://{}:{}@{}/{}?directconnection=true&appName=gatekeeper&retryWrites=false",
			username, password, epAddr, collection
		);

		let redisClient = match redis::Client::open(format!("redis://{}", redisAddr)) {
			Ok(c) => c,
			Err(e) => {
				error!("error connecting to redis: {e}");
				return Err(mongodb::error::Error::custom("Failed to connect to Redis"));
			}
		};

		let c = Client::with_uri_str(mongoEP.clone()).await;
		match c {
			Ok(c) => Ok(Arc::new(DataStore {
				mongoClient: RwLock::new(c),
				collectionName: collection,
				vault,
				serverEP: epAddr.clone(),
				redis: redisClient,
				dev,
			})),
			Err(e) => Err(e),
		}
	}
	pub async fn NewNamespace(&self, domain: &Namespace) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async { self.insertUnique("servicedomains", domain, doc! {"base": &domain.base}, None).await })
			.await
	}
	pub async fn NewService(&self, svc: &Service, parentDomain: &String) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let client = self.mongoClient.read().await;
			let mut newSvcSession = client.start_session().await.unwrap();
			// let mut newSvcSession = self.client.read().unwrap().start_session().await.unwrap();

			let _ = newSvcSession.start_transaction().await;
			match self.insertUnique("services", svc, doc! {"name": &svc.name}, Some(&mut newSvcSession)).await {
				Ok(r) => {
					if r {
						self.addServiceToNamespace(&svc.name, parentDomain, &mut newSvcSession).await
					} else {
						Ok(false)
					}
				}
				Err(e) => {
					let _ = newSvcSession.abort_transaction().await;
					Err(e)
				}
			}
		})
		.await
	}
	pub async fn AddRouteAliasToService(&self, id: &String, alias: &Alias) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let coll: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection::<Namespace>("services");
			let svc = self.GetServiceByID(id).await;
			match svc {
				Ok(Some(s)) => {
					if !s.route_aliases.is_empty() && s.route_aliases.contains(alias) {
						return Err(mongodb::error::Error::custom("this service already contains a similar alias."));
					}
					let alias_doc = mongodb::bson::to_document(alias)?;
					match coll.update_one(doc! {"id": id}, doc! {"$addToSet": doc!{"routeAliases": doc!{"$each": [alias_doc]} }}).await {
						Ok(_) => Ok(true),
						Err(e) => Err(e),
					}
				}
				Ok(None) => Err(mongodb::error::Error::custom("invalid ID specified")),
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub async fn GetNamespaceByName(&self, name: &String) -> Result<Option<Namespace>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let coll: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection::<Namespace>("servicedomains");
			let cursor = coll.find_one(doc! {"base": name}).await;
			match cursor {
				Ok(Some(sd)) => Ok(Some(sd)),
				Ok(None) => Ok(None),
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub async fn GetNamespaceByID(&self, id: &String) -> Result<Option<Namespace>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let coll: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection::<Namespace>("servicedomains");
			let cursor = coll.find_one(doc! {"id": id}).await;
			match cursor {
				Ok(Some(sd)) => Ok(Some(sd)),
				Ok(None) => Ok(None),
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub async fn GetNamespaceNames(&self) -> Result<Vec<String>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let NamespacesColl: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection("servicedomains");
			let cursor = NamespacesColl.find(doc! {}).await; //.run()?;
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
		})
		.await
	}
	pub async fn GetNamespaces(&self) -> Result<Vec<Namespace>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let NamespacesColl: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection("servicedomains");
			let cursor = NamespacesColl.find(doc! {}).await; //.run()?;
			let mut domains: Vec<Namespace> = Vec::new();

			match cursor {
				Ok(mut c) => {
					while let Some(doc) = c.try_next().await? {
						domains.push(doc);
					}
					Ok(domains)
				}
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub async fn GetServiceByName(&self, name: &String) -> Result<Option<Service>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let servicesColl: Collection<Service> = self.mongoClient.read().await.database(&self.collectionName).collection("services");
			match servicesColl.find_one(doc! {"name": name}).await {
				Ok(Some(svc)) => return Ok(Some(svc)),
				Ok(None) => return Ok(None),
				Err(e) => return Err(e),
			};
		})
		.await
	}
	pub async fn GetServiceByID(&self, id: &String) -> Result<Option<Service>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let servicesColl: Collection<Service> = self.mongoClient.read().await.database(&self.collectionName).collection("services");
			match servicesColl.find_one(doc! {"id": id}).await {
				Ok(Some(svc)) => return Ok(Some(svc)),
				Ok(None) => return Ok(None),
				Err(e) => return Err(e),
			};
		})
		.await
	}
	pub async fn GetAllServices(&self) -> Result<Vec<Service>, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let servicesColl: Collection<Service> = self.mongoClient.read().await.database(&self.collectionName).collection("services");
			let cursor = servicesColl.find(doc! {}).await; //.run()?;
			let mut svcs: Vec<Service> = Vec::new();

			match cursor {
				Ok(mut c) => {
					while let Some(doc) = c.try_next().await? {
						svcs.push(doc);
					}
					Ok(svcs)
				}
				Err(e) => {
					error!("{e}");
					Err(e)
				}
			}
		})
		.await
	}
	pub async fn GetServiceEDLSetting(&self, name: &String) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let servicesColl: Collection<Service> = self.mongoClient.read().await.database(&self.collectionName).collection("services");
			match servicesColl.find_one(doc! {"name": name}).await {
				Ok(Some(svc)) => return Ok(svc.allows_external_device_login),
				Ok(None) => return Ok(false),
				Err(e) => return Err(e),
			};
		})
		.await
	}
	pub async fn DeleteDomain(&self, id: &String) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async {
			match self.GetNamespaceByID(id).await {
				Ok(Some(sd)) => {
					if sd.services.is_empty() {
						let coll: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection::<Namespace>("servicedomains");
						match coll.delete_one(doc! {"id": id}).await {
							Ok(r) => Ok(r.deleted_count > 0),
							Err(e) => Err(e),
						}
					} else {
						error!("{} still has attached services. please delete the attached service before attempting to delete the domain", sd.base);
						return Err(mongodb::error::Error::custom(format!(
							"{} still has attached services. please delete the attached service before attempting to delete the domain.",
							sd.base
						)));
					}
				}
				Ok(None) => {
					error!("specified domain doesn't exist");
					return Err(mongodb::error::Error::custom("specified domain doesn't exist"));
				}
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub async fn DeleteService(&self, id: &String) -> Result<bool, mongodb::error::Error> {
		self.retryableQuery(|| async {
			let servicesColl: Collection<Service> = self.mongoClient.read().await.database(&self.collectionName).collection("services");
			match servicesColl.delete_one(doc! {"id": id}).await {
				Ok(r) => Ok(r.deleted_count > 0),
				Err(e) => Err(e),
			}
		})
		.await
	}
	pub fn ReadStringFromRedis(&self, key: String) -> Result<String, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<String> = conn.get(key);
				match result {
					Ok(v) => Ok(v),
					Err(e) => Err(format!("ReadStringFromRedis: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub fn WriteStringToRedis(&self, key: &String, value: &String) -> Result<bool, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<()> = conn.set(key, value);
				match result {
					Ok(_) => Ok(true),
					Err(e) => Err(format!("WriteStringToRedis: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub fn WriteStringToRedisWithTTL(&self, key: &String, value: &String, ttl: u64) -> Result<bool, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<()> = conn.set_ex(key, value, ttl);
				match result {
					Ok(_) => Ok(true),
					Err(e) => Err(format!("WriteStringToRedisWithTTL: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	async fn addServiceToNamespace(&self, serviceName: &String, domainName: &String, session: &mut ClientSession) -> Result<bool, mongodb::error::Error> {
		//TODO: use retryable query.
		// self.retryableQuery(|| async {
		let coll: Collection<Namespace> = self.mongoClient.read().await.database(&self.collectionName).collection::<Namespace>("servicedomains");
		match coll
			.update_one(doc! {"base": domainName}, doc! {"$addToSet": doc!{"services": doc!{"$each": [serviceName]}}})
			.session(&mut *session)
			.await
		{
			Ok(r) => {
				if r.modified_count > 0 {
					let _ = session.commit_transaction().await;
					Ok(true)
				} else {
					Ok(false)
				}
			}
			Err(e) => Err(e),
		}
		// }).await
	}
	async fn reconnect(&self) -> Result<Client, mongodb::error::Error> {
		let newCreds = self.vault.GetDBCredentials(self.dev).await.unwrap();

		let mongoEP = format!(
			"mongodb://{}:{}@{}/{}?directconnection=true&appName=gatekeeper&retryWrites=false",
			&newCreds.username, &newCreds.password, self.serverEP, self.collectionName
		);

		Client::with_uri_str(mongoEP.clone()).await
	}
	async fn retryableQuery<ResultType, AsyncFn: Future<Output = Result<ResultType, mongodb::error::Error>>, F: Fn() -> AsyncFn>(&self, queryFn: F) -> Result<ResultType, mongodb::error::Error>
	where
		F: Fn() -> AsyncFn,
	{
		match queryFn().await {
			Err(e) => {
				if matches!(e.kind.as_ref(), ErrorKind::Authentication { .. }) {
					let _ = self.mongoClient.read().await.clone().shutdown();
					match self.reconnect().await {
						Ok(c) => {
							let mut client = self.mongoClient.write().await;
							*client = c;
							return queryFn().await;
						}
						Err(e) => return Err::<ResultType, mongodb::error::Error>(e),
					}
				}
				Err(e)
			}
			Ok(r) => Ok(r),
		}
	}
	async fn insertUnique<T>(&self, collName: &str, doc: &T, criteriaForUnique: Document, session: Option<&mut ClientSession>) -> Result<bool, mongodb::error::Error>
	where
		T: Serialize + DeserializeOwned + Send + Sync + Clone,
	{
		let coll: Collection<T> = self.mongoClient.read().await.database(&self.collectionName).collection::<T>(collName);
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
