/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use uuid::Uuid;

use super::{cert_svc::CertManagerSvc, v1::*};
use crate::{
	data::DataStore,
	services::v1::{Service, ServiceDomain},
	vault::Certificate,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ConfigServiceImpl {
	db: Arc<DataStore>,
	certMgr: Arc<CertManagerSvc>,
}

impl ConfigServiceImpl {
	pub fn new(db: Arc<DataStore>, certMgr: Arc<CertManagerSvc>) -> Self {
		ConfigServiceImpl { db, certMgr }
	}
	pub async fn NewService(&self, svc: &Service, parentDomain: &String) -> Result<(String, Certificate), String> {
		let mut svc = svc.clone();
		svc.id = Uuid::now_v7().to_string();

		let svcCert: Certificate;

		match self.db.GetDomainByName(parentDomain).await {
			Ok(Some(_)) => {
				match self.certMgr.GenerateServiceCert(&svc.name).await {
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
	pub async fn NewServiceDomain(&self, domain: &ServiceDomain) -> Result<String, String> {
		let mut domain = domain.clone();
		domain.id = Uuid::now_v7().to_string();
		match self.db.NewServiceDomain(&domain).await {
			Ok(success) => {
				if success {
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
	pub async fn GetDomainByName(&self, name: &String) -> Result<Option<ServiceDomain>, String> {
		match self.db.GetDomainByName(name).await {
			Ok(Some(d)) => Ok(Some(d)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetDomainByID(&self, id: &String) -> Result<Option<ServiceDomain>, String> {
		match self.db.GetDomainByID(id).await {
			Ok(Some(d)) => Ok(Some(d)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn DeleteDomain(&self, id: &String) -> Result<bool, String> {
		self.db.DeleteDomain(id).await.map_err(|e| String::from(e.to_string()))
	}
	pub async fn DeleteService(&self, id: &String) -> Result<bool, String> {
		self.db.DeleteService(id).await.map_err(|e| String::from(e.to_string()))
	}
	pub async fn RenewServiceCredentials(&self, name: &String) -> Result<ServiceCredentials, String> {
		match self.certMgr.GenerateServiceCert(name).await {
			Ok(c) => {
				let ca_chain = c.ca_chain.unwrap();
				let x = ca_chain.iter().fold(String::new(), |acc, i| acc + "\n" + i);
				return Ok(ServiceCredentials { ca_cert: x, certificate: c.certificate, expires_at: c.expiration.unwrap_or(0), issuer_cert: c.issuing_ca, private_key: c.private_key });
			}
			Err(e) => return Err(e),
		};
	}
}
