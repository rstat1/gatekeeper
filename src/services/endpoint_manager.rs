/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use crate::data::{self, Domain, GatekeeperService};
use std::{
	collections::HashMap,
	fmt::{Debug, Display},
	net::SocketAddr,
	sync::Arc,
	time::Duration,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use super::v1::NewServiceEndpoint;

pub trait RemoveElem<T> {
	fn remove_elem<F>(&mut self, predicate: F) -> Option<T>
	where
		F: Fn(&T) -> bool;
}

struct HealthChecker {
	client: Arc<EndpointManagerImpl>,
}

struct RegisteredEndpoint {
	pub address: SocketAddr,
	pub healthCheckRoute: String,
}

pub struct EndpointManagerImpl {
	domains: Vec<Domain>,
	_db: Arc<data::DataStore>,
	svcsList: Vec<GatekeeperService>,
	epMap: Mutex<HashMap<String, Vec<RegisteredEndpoint>>>,
}

impl Display for RegisteredEndpoint {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "(addr: {}, hcr: {})", self.address, self.healthCheckRoute)
	}
}

impl Debug for RegisteredEndpoint {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RegisteredEndpoint")
			.field("address", &self.address)
			.field("healthCheckRoute", &self.healthCheckRoute)
			.finish()
	}
}

impl<T> RemoveElem<T> for Vec<T> {
	fn remove_elem<F>(&mut self, predicate: F) -> Option<T>
	where
		F: Fn(&T) -> bool,
	{
		self.iter().position(predicate).map(|index| self.remove(index))
	}
}

impl EndpointManagerImpl {
	pub async fn new(data: Arc<data::DataStore>, svcsList: Vec<GatekeeperService>, healthPingInterval: Option<u64>) -> Result<Arc<Self>, String> {
		match data.GetDomains().await {
			Ok(d) => {
				let epmgr = Arc::new(EndpointManagerImpl { _db: data, svcsList, domains: Vec::from(d), epMap: Mutex::new(HashMap::new()) });
				epmgr.startHealthCheck(healthPingInterval.unwrap_or(300));
				Ok(epmgr)
			}
			Err(e) => Err(e.to_string()),
		}
	}

	pub fn IsValidDomain(&self, domain: &String) -> bool {
		for d in &self.domains {
			if d.base == *domain {
				return true;
			}
		}
		warn!("didn't find a valid Domain for {}", domain);
		false
	}

	pub fn RegisterServiceEndpoint(&self, request: &NewServiceEndpoint) -> Result<bool, String> {
		let epMap = self.epMap.try_lock();

		if !self.svcsList.iter().any(|s| s.name == request.service_name) {
			return Err("unknown service".to_string());
		}

		match epMap {
			Ok(mut m) => {
				if let Some(eps) = m.get_mut(&request.endpoint_name) {
					debug!("added endpoint {} to service {} with hcr {}", &request.endpoint, &request.service_name, &request.health_check_route);
					eps.push(RegisteredEndpoint { address: request.endpoint.parse().unwrap(), healthCheckRoute: request.health_check_route.clone() });
				} else {
					debug!("added new endpoint {} at {} with hcr {}", &request.endpoint_name, &request.endpoint, &request.health_check_route);
					m.insert(
						request.endpoint_name.clone(),
						vec![RegisteredEndpoint { address: request.endpoint.parse().unwrap(), healthCheckRoute: request.health_check_route.clone() }],
					);
				}
			}
			Err(e) => {
				error!("{:?}", e);
				return Err(e.to_string());
			}
		}

		Ok(true)
	}
	pub fn GetServiceEndpoint(&self, name: &String) -> Option<SocketAddr> {
		let epMap = self.epMap.try_lock();
		match epMap {
			Ok(m) => {
				if let Some(eps) = m.get(name) {
					if eps.len() > 1 {
						//TODO: Random selection?
						return Some(eps[0].address.clone());
					} else if eps.len() != 0 {
						return Some(eps[0].address.clone());
					}
				}
				return None;
			}
			Err(e) => {
				error!("{:?}", e)
			}
		}
		None
	}
	pub fn RemoveServiceEndpoint(&self, name: &String, endpoint: SocketAddr) {
		let epMap = self.epMap.try_lock();
		match epMap {
			Ok(mut m) => {
				if let Some(eps) = m.get_mut(name) {
					if eps.len() != 0 {
						eps.remove_elem(|e| e.address == endpoint);
					}
				}
			}
			Err(e) => {
				error!("{:?}", e)
			}
		}
	}
	fn startHealthCheck(self: &Arc<Self>, ttl: u64) {
		let hc = Arc::new(HealthChecker { client: Arc::clone(&self) });
		hc.StartHealthCheck(ttl);
	}
}
impl HealthChecker {
	pub fn StartHealthCheck(self: &Arc<Self>, healthCheckInterval: u64) {
		let self_clone = Arc::clone(self);
		tokio::spawn(async move {
			let hcClient = reqwest::Client::builder().connect_timeout(Duration::from_secs(1)).build().unwrap();
			loop {
				tokio::time::sleep(Duration::from_secs(healthCheckInterval)).await;
				let hcs = self_clone.client.epMap.try_lock();
				match hcs {
					Ok(mut m) => {
						for (key, val) in m.iter_mut() {
							if !val.is_empty() {
								let mut to_remove = Vec::new();
								for rep in val.iter() {
									debug!("checking svc: {key}, rep: {rep}");
									match hcClient.get(rep.healthCheckRoute.clone()).send().await {
										Ok(r) => match r.text().await {
											Ok(b) => {
												if b != "pong" {
													error!("inproper response, adding {key} endpoint to removal list");
													to_remove.push(rep.address);
												}
											}
											Err(e) => {
												error!("adding {key} endpoint to removal list due to an error: {}", e);
												to_remove.push(rep.address);
											}
										},
										Err(e) => {
											if e.is_timeout() || e.is_connect() {
												error!("adding {key} endpoint to removal list because it failed to respond to a ping");
												to_remove.push(rep.address);
											}
										}
									}
								}
								for addr in to_remove {
									val.remove_elem(|e| e.address == addr);
								}
							}
						}
					}
					Err(e) => {
						error!("{:?}", e)
					}
				}
			}
		});
	}
}
