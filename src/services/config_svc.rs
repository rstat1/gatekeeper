/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use tracing::error;
use uuid::Uuid;

use super::v1::*;
use crate::{
	data::DataStore,
	pki::{
		status_api::{CertStatusRegistry, CertificateType, RegisteredCertificate},
		CertManagerSvc,
	},
	services::{
		endpoint_manager::EndpointManagerImpl,
		v1::{Namespace, Service},
	},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ConfigServiceImpl {
	db: Arc<DataStore>,
	cmSvc: Arc<CertManagerSvc>,
	epMgr: Arc<EndpointManagerImpl>,
	certStatusRegistry: Arc<CertStatusRegistry>,
}

impl ConfigServiceImpl {
	pub fn new(db: Arc<DataStore>, cmSvc: Arc<CertManagerSvc>, epMgr: Arc<EndpointManagerImpl>, certStatusRegistry: Arc<CertStatusRegistry>) -> Self {
		ConfigServiceImpl { db, cmSvc, epMgr, certStatusRegistry }
	}
	pub async fn NewService(&self, svc: &Service, parentDomain: &String) -> Result<(String, ServiceCredentials), String> {
		let svcCert: ServiceCredentials;
		let mut svc = svc.clone();
		svc.id = Uuid::now_v7().to_string();

		match self.db.GetNamespaceByName(parentDomain).await {
			Ok(Some(_)) => {
				match self.cmSvc.GenerateServiceCert(&svc.name).await {
					Ok(c) => svcCert = c,
					Err(e) => return Err(e),
				};
				match self.db.NewService(&svc, parentDomain).await {
					Ok(r) => {
						if r {
							self.certStatusRegistry.Add(RegisteredCertificate { issuedFor: svc.name, certType: CertificateType::Endpoint }).await;
							Ok((svc.id, svcCert))
						} else {
							Err("already exists".to_string())
						}
					}
					Err(e) => Err(e.to_string()),
				}
			}
			Ok(None) => Err(format!("unknown namespace {}", parentDomain)),
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
							} else {
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
						Ok(()) => {}
						Err(e) => {
							error!("{e}");
							return Err(e);
						}
					}
					let name = self.epMgr.NSIDToName(id).await;
					self.certStatusRegistry.Remove(&name).await;
					Ok(true)
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
			Ok(name) => match self.db.DeleteService(id).await {
				Ok(r) => {
					if r {
						match self.cmSvc.RevokeServiceCert(&name).await {
							Ok(()) => {
								self.epMgr.RemoveService(name);
								return Ok(true);
							}
							Err(e) => return Err(format!("DeleteService: RevokeServiceCert: {}",e)),
						}
					} else {
						return Ok(false);
					}
				}
				Err(e) => Err(format!("DeleteService: {}",e))
			},
			Err(_) => Err("failed to convert service name to ID".to_string()),
		}
	}
	pub async fn RenewServiceCredentials(&self, name: &String) -> Result<ServiceCredentials, String> {
		match self.cmSvc.GenerateServiceCert(name).await {
			Ok(c) => {
				return Ok(c);
			}
			Err(e) => return Err(e),
		};
	}
}
