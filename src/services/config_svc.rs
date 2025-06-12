/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use tracing::error;
use uuid::Uuid;

use super::{cert_svc::CertManagerSvc, v1::*};
use crate::{
	data::DataStore,
	services::{
		endpoint_manager::EndpointManagerImpl,
		v1::{Namespace, Service},
	},
	vault::Certificate,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ConfigServiceImpl {
	db: Arc<DataStore>,
	cmSvc: Arc<CertManagerSvc>,
	epMgr: Arc<EndpointManagerImpl>,
}

impl ConfigServiceImpl {
	pub fn new(db: Arc<DataStore>, cmSvc: Arc<CertManagerSvc>, epMgr: Arc<EndpointManagerImpl>) -> Self {
		ConfigServiceImpl { db, cmSvc, epMgr }
	}
	pub async fn NewService(&self, svc: &Service, parentDomain: &String) -> Result<(String, Certificate), String> {
		let svcCert: Certificate;
		let mut svc = svc.clone();
		svc.id = Uuid::now_v7().to_string();

		match self.db.GetNamespaceByName(parentDomain).await {
			Ok(Some(_)) => {
				match self.cmSvc.GenerateServiceCert(&svc.name, true).await {
					Ok(c) => svcCert = c,
					Err(e) => return Err(e),
				};
				match self.db.NewService(&svc, parentDomain).await {
					Ok(r) => {
						if r {
							Ok((svc.id, svcCert))
						} else {
							Err("already exists".to_string())
						}
					}
					Err(e) => Err(e.to_string()),
				}
			}
			Ok(None) => Err(format!("unknown service domain {}", parentDomain)),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn NewNamespace(&self, domain: &Namespace) -> Result<String, String> {
		let mut domain = domain.clone();
		domain.id = Uuid::now_v7().to_string();
		match self.db.NewNamespace(&domain).await {
			Ok(success) => {
				if success {
					let domain_id = domain.id.clone();
					if domain.gatekeeper_managed_certs {
						let cert_mgr = self.cmSvc.clone();
						tokio::spawn(async move {
							let r = cert_mgr.GenerateACMECert(&domain.base, &domain_id, None).await;
							if r.is_err() {
								error!("{}", r.unwrap_err());
							}
						});
					}
					return Ok(domain.id);
				}
				Err("already exists".to_string())
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn NewRouteAlias(&self, alias: &AliasRequest) -> Result<String, String> {
		match self.db.AddRouteAliasToService(&alias.id, &Alias { alias: alias.alias.clone(), route: alias.route.clone() }).await {
			Ok(success) => {
				if success {
					Ok("success".to_string())
				} else {
					Err("".to_string())
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetServiceByName(&self, name: &String) -> Result<Option<Service>, String> {
		match self.db.GetServiceByName(name).await {
			Ok(Some(gks)) => Ok(Some(gks)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetServiceByID(&self, id: &String) -> Result<Option<Service>, String> {
		match self.db.GetServiceByID(id).await {
			Ok(Some(gks)) => Ok(Some(gks)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetNamespaceByName(&self, name: &String) -> Result<Option<Namespace>, String> {
		match self.db.GetNamespaceByName(name).await {
			Ok(Some(d)) => Ok(Some(d)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetNamespaceByID(&self, id: &String) -> Result<Option<Namespace>, String> {
		match self.db.GetNamespaceByID(id).await {
			Ok(Some(d)) => Ok(Some(d)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn DeleteNamespace(&self, id: &String) -> Result<bool, String> {
		match self.db.DeleteDomain(id).await {
			Ok(success) => {
				if success {
					match self.cmSvc.RevokeNSCert(id).await {
						Ok(()) => Ok(true),
						Err(e) => {
							error!("{e}");
							Err(e)
						}
					}
				} else {
					Ok(false)
				}
			}
			Err(e) => {
				if let Some(actualErr) = e.get_custom::<String>() {
					error!("{actualErr}");
					Err(actualErr.to_string())
				} else {
					error!("this is why error STRINGS are superior to error structs {e}");
					Err(e.to_string())
				}
			}
		}
	}
	pub async fn DeleteService(&self, id: &String) -> Result<bool, String> {
		match self.epMgr.ServiceIdToName(id) {
			Ok(name) => {
				let result = self.cmSvc.RevokeServiceCert(&name).await;
				if result.is_ok() {
					self.db.DeleteService(id).await.map_err(|e| String::from(e.to_string()))
				} else {
					Err(result.unwrap_err())
				}
			},
			Err(_) => Err("failed to convert service name to ID".to_string()),
		}
	}
	pub async fn RenewServiceCredentials(&self, name: &String) -> Result<ServiceCredentials, String> {
		match self.cmSvc.GenerateServiceCert(name, false).await {
			Ok(c) => {
				let ca_chain = c.ca_chain.unwrap();
				let x = ca_chain.iter().fold(String::new(), |acc, i| acc + "\n" + i);
				return Ok(ServiceCredentials { ca_cert: x, certificate: c.certificate, expires_at: c.expiration.unwrap_or(0), issuer_cert: c.issuing_ca, private_key: c.private_key });
			}
			Err(e) => return Err(e),
		};
	}
}
