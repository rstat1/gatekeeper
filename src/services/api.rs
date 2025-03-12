/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use uuid::Uuid;

use super::{cert_svc::CertManagerSvc, v1::*};
use crate::{
	data::{DataStore, Domain, GatekeeperService},
	vault::Certificate,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct APIServiceImpl {
	db: Arc<DataStore>,
	certMgr: Arc<CertManagerSvc>,
}

impl APIServiceImpl {
	pub fn new(db: Arc<DataStore>, certMgr: Arc<CertManagerSvc>) -> Self {
		APIServiceImpl { db, certMgr }
	}
	pub async fn NewService(&self, svc: &Service, parentDomain: &String) -> Result<(String, Certificate), String> {
		let svc: GatekeeperService = GatekeeperService {
			id: Uuid::now_v7().to_string(),
			name: svc.name.clone(),
			internal: svc.internal,
			healthCheckRoute: svc.health_check_route.clone(),
			securityPolices: None,
			isFrostSvc: svc.is_frost_service,
		};
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
		let d: Domain = Domain { id: Uuid::now_v7().to_string(), base: domain.base.clone(), frostCompatEnabled: false, securityPolicies: None, services: Vec::new() };

		match self.db.NewServiceDomain(&d).await {
			Ok(success) => {
				if success {
					return Ok(d.id);
				}
				Err("already exists".to_string())
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetServiceByName(&self, name: &String) -> Result<Option<GatekeeperService>, String> {
		match self.db.GetServiceByName(name).await {
			Ok(Some(gks)) => Ok(Some(gks)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetServiceByID(&self, id: &String) -> Result<Option<GatekeeperService>, String> {
		match self.db.GetServiceByID(id).await {
			Ok(Some(gks)) => Ok(Some(gks)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetDomainByName(&self, name: &String) -> Result<Option<Domain>, String> {
		match self.db.GetDomainByName(name).await {
			Ok(Some(d)) => Ok(Some(d)),
			Ok(None) => Ok(None),
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn GetDomainByID(&self, id: &String) -> Result<Option<Domain>, String> {
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
}
