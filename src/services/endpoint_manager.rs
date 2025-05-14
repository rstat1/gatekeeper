/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use crate::{
	data::{self},
	services::v1::{Service, ServiceDomain},
	vault::Certificate as VaultCertificate,
};
use bytes::Bytes;
use http::Uri;
use pingora::{
	connectors::http::v1::Connector,
	protocols::ALPN,
	tls::{pkey::PKey, x509::X509},
	upstreams::peer::PeerOptions,
	utils::tls::CertKey,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use std::{
	collections::HashMap,
	fmt::{Debug, Display},
	net::SocketAddr,
	sync::Arc,
	time::Duration,
};
use tokio::sync::Mutex;
use tracing::{debug, error, warn};

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
	pub isExternalDevice: bool,
	pub healthCheckRoute: String,
	pub deviceID: Option<String>,
	pub serviceName: String,
}

pub struct EndpointManagerImpl {
	domains: Vec<ServiceDomain>,
	gkCert: Arc<VaultCertificate>,
	svcsList: Mutex<Vec<Service>>,
	epMap: Mutex<HashMap<String, Vec<RegisteredEndpoint>>>,
	aliasToSvc: HashMap<String, String>,
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
	pub async fn new(data: Arc<data::DataStore>, svcsList: Vec<Service>, healthPingInterval: Option<u64>, gkCert: Arc<VaultCertificate>) -> Result<Arc<Self>, String> {
		let mut aliasToSvc: HashMap<String, String> = HashMap::default();
		match data.GetDomains().await {
			Ok(d) => {
				for svc in &svcsList {
					for alias in &svc.route_aliases {
						aliasToSvc.insert(alias.alias.clone(), svc.name.clone());
					}
				}

				let epmgr = Arc::new(EndpointManagerImpl { svcsList: Mutex::new(svcsList), domains: Vec::from(d), epMap: Mutex::new(HashMap::new()), gkCert, aliasToSvc });
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

	pub fn IsValidService(&self, svcName: &String) -> (bool, String) {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if svcList.iter().any(|s| s.name == *svcName) {
					(true, "".to_string())
				} else if self.aliasToSvc.contains_key(svcName) {
					(true, self.aliasToSvc[svcName].clone())
				} else {
					(false, "".to_string())
				}
			}
			Err(_) => (false, "".to_string()),
		}
	}

	pub fn ServiceIdToName(&self, id: &String) -> Result<String, bool> {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if let Some(service) = svcList.iter().find(|s| *s.id == *id) {
					Ok(service.name.clone())
				} else {
					Err(false)
				}
			}
			Err(_) => Err(false),
		}
	}

	pub fn IsRPCGatewayEnabled(&self, svcName: &String) -> bool {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if let Some(service) = svcList.iter().find(|s| *s.name == *svcName) {
					service.enable_grpc_gateway
				} else {
					false
				}
			}
			Err(_) => false,
		}
	}

	pub fn RegisterServiceEndpoint(&self, request: &NewServiceEndpoint) -> Result<bool, String> {
		let epMap = self.epMap.try_lock();
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if !svcList.iter().any(|s| s.name == request.service_name) {
					return Err("unknown service".to_string());
				}
			}
			Err(_) => todo!(),
		}

		match epMap {
			Ok(mut m) => {
				if let Some(eps) = m.get_mut(&request.endpoint_name) {
					debug!("added endpoint {} to service {} with hcr {}", &request.endpoint, &request.service_name, &request.health_check_route);
					eps.push(RegisteredEndpoint {
						serviceName: request.service_name.clone(),
						address: request.endpoint.parse().unwrap(),
						healthCheckRoute: request.health_check_route.clone(),
						isExternalDevice: false,
						deviceID: None,
					});
				} else {
					debug!("added new endpoint {} at {} with hcr {}", &request.endpoint_name, &request.endpoint, &request.health_check_route);
					m.insert(
						request.endpoint_name.clone(),
						vec![RegisteredEndpoint {
							serviceName: request.service_name.clone(),
							address: request.endpoint.parse().unwrap(),
							healthCheckRoute: request.health_check_route.clone(),
							isExternalDevice: false,
							deviceID: None,
						}],
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
	pub fn AddClientDeviceToPingerList(&self, service_name: &String, deviceID: String, endpoint: String) -> Result<bool, String> {
		let epMap = self.epMap.try_lock();

		if service_name.is_empty() || deviceID.is_empty() || endpoint.is_empty() {
			return Err("one or more arguments are invalid".to_string());
		}

		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if !svcList.iter().any(|s| s.name == *service_name) {
					return Err("unknown service".to_string());
				}
			}
			Err(_) => todo!(),
		}

		match epMap {
			Ok(mut m) => {
				if let Some(eps) = m.get_mut(&deviceID) {
					debug!("added endpoint {} to service {} with hcr {}", &endpoint, service_name, &"/ping".to_string());
					eps.push(RegisteredEndpoint {
						serviceName: service_name.clone(),
						address: endpoint.parse().unwrap(),
						healthCheckRoute: "/ping".to_string(),
						isExternalDevice: true,
						deviceID: Some(deviceID),
					});
				} else {
					debug!("added new endpoint {} at {} with hcr {}", &deviceID, &endpoint, "/ping".to_string());
					m.insert(
						deviceID.clone(),
						vec![RegisteredEndpoint {
							serviceName: service_name.clone(),
							address: endpoint.parse().unwrap(),
							healthCheckRoute: "/ping".to_string(),
							isExternalDevice: true,
							deviceID: Some(deviceID),
						}],
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
	pub fn AddServiceToKnownList(&self, newSvc: &Service) {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(mut svcList) => {
				if !svcList.contains(newSvc) {
					svcList.push(newSvc.clone());
				}
			}
			Err(e) => error!("{:?}", e),
		}
	}

	fn startHealthCheck(self: &Arc<Self>, ttl: u64) {
		let hc = Arc::new(HealthChecker { client: Arc::clone(&self) });
		hc.StartHealthCheck(ttl, self.gkCert.clone());
	}
}
impl HealthChecker {
	pub fn StartHealthCheck(self: &Arc<Self>, healthCheckInterval: u64, gkCert: Arc<VaultCertificate>) {
		let self_clone = Arc::clone(self);
		tokio::spawn(async move {
			let caChain = gkCert.ca_chain.as_ref().unwrap();

			let cert = X509::from_pem(&Bytes::from(gkCert.certificate.clone())).unwrap();
			let caInt = X509::from_pem(&Bytes::from(caChain[0].clone())).unwrap();
			let caRoot = X509::from_pem(&Bytes::from(caChain[1].clone())).unwrap();
			let pKey = PKey::private_key_from_pem(&Bytes::from(gkCert.private_key.clone())).unwrap();
			let value = Arc::new(CertKey::new(vec![cert], pKey));

			let connector = Connector::new(None);

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
									let addrParts = rep.healthCheckRoute.split("/").collect::<Vec<&str>>();
									let addr: SocketAddr = addrParts[2].to_string().parse().unwrap();
									let mut peer = HttpPeer::new(addr, true, rep.serviceName.clone());

									let mut peerOpts = PeerOptions::new();

									peer.client_cert_key = Some(value.clone());
									peerOpts.alpn = ALPN::H1;
									peerOpts.ca = Some(Arc::new(Box::new([caInt.clone(), caRoot.clone()])));
									peer.options = peerOpts;

									let hcr: Uri = rep.healthCheckRoute.parse().unwrap();

									match connector.get_http_session(&peer).await {
										Ok((mut http, _reused)) => {
											let mut new_request = RequestHeader::build("GET", hcr.path().as_bytes(), None).unwrap();
											new_request.insert_header("Host", key.clone()).unwrap();
											http.write_request_header(Box::new(new_request)).await.unwrap();
											http.finish_body().await.unwrap();
											http.read_response().await.unwrap();
											let mut response_body = String::new();
											while let Some(chunk) = http.read_body_ref().await.unwrap() {
												response_body.push_str(&String::from_utf8_lossy(&chunk));
											}

											if !rep.isExternalDevice {
												if response_body != "pong" {
													error!("incorrect response, adding endpoint '{key}' to removal list");
													to_remove.push(rep.address.to_string());
												}
											} else {
												if let Some(devID) = &rep.deviceID {
													if response_body != *devID {
														error!("incorrect response, adding device '{key}' to removal list");
														to_remove.push(devID.clone());
													}
												}
											}
										}
										Err(e) => {
											error!("incorrect response, adding endpoint or device '{key}' to removal list: {:?}", e);
											to_remove.push(rep.address.to_string());
										}
									}
								}
								for addr in to_remove {
									val.remove_elem(|e| {
										if e.isExternalDevice {
											return addr == *e.deviceID.as_ref().unwrap_or(&"".to_string());
										} else {
											e.address.to_string() == addr
										}
									});
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
