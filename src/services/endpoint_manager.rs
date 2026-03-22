/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use crate::{
	data::{self},
	pki::{status_api::*, CertManagerSvc},
	services::v1::{Namespace, Service, ServiceCredentials},
	RemoveElem, SYSTEM_CONFIG,
};
use bytes::Bytes;
use chrono::Utc;
use http::{header, Uri};
use pingora::{
	connectors::http::v1::Connector,
	protocols::ALPN,
	tls::{pkey::PKey, x509::X509},
	upstreams::peer::PeerOptions,
	utils::tls::CertKey,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use rand::Rng;
use std::{
	collections::HashMap,
	fmt::{Debug, Display},
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::Arc,
	time::Duration,
};
use tokio::sync::{watch::Receiver, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::v1::NewServiceEndpoint;

struct HealthChecker {
	client: Arc<EndpointManagerImpl>,
}
struct CertChecker {
	client: Arc<EndpointManagerImpl>,
}

#[derive(Clone)]
struct RegisteredEndpoint {
	pub address: SocketAddr,
	pub isExternalDevice: bool,
	pub healthCheckRoute: String,
	pub deviceID: Option<String>,
	pub serviceName: String,
	pub epID: Option<String>,
	pub runningOnK8S: bool,
}
#[derive(Debug)]
pub struct EndpointManagerImpl {
	cmSvc: Arc<CertManagerSvc>,
	domains: RwLock<Vec<Namespace>>,
	svcsList: Mutex<Vec<Service>>,
	aliasToSvc: HashMap<String, String>,
	certStatusRegistry: Arc<CertStatusRegistry>,
	epMap: Mutex<HashMap<String, Vec<RegisteredEndpoint>>>,
	pub certUpdateChan: Receiver<(ServiceCredentials, String)>,
}

impl Display for RegisteredEndpoint {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "(addr: {}, hcr: {}, svc: {})", self.address, self.healthCheckRoute, self.serviceName)
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

impl Default for RegisteredEndpoint {
	fn default() -> Self {
		Self {
			address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
			isExternalDevice: Default::default(),
			healthCheckRoute: Default::default(),
			deviceID: Default::default(),
			serviceName: Default::default(),
			epID: Default::default(),
			runningOnK8S: Default::default(),
		}
	}
}

impl EndpointManagerImpl {
	pub async fn new(
		data: Arc<data::DataStore>, svcsList: Vec<Service>, cmSvc: Arc<CertManagerSvc>, certUpdateChan: Receiver<(ServiceCredentials, String)>, certStatusRegistry: Arc<CertStatusRegistry>,
	) -> Result<Arc<Self>, String> {
		let mut aliasToSvc: HashMap<String, String> = HashMap::default();
		match data.GetNamespaces().await {
			Ok(d) => {
				for svc in &svcsList {
					for alias in &svc.route_aliases {
						aliasToSvc.insert(alias.alias.clone(), svc.name.clone());
					}
				}

				let epmgr = Arc::new(EndpointManagerImpl {
					svcsList: Mutex::new(svcsList),
					domains: RwLock::new(Vec::from(d)),
					epMap: Mutex::new(HashMap::new()),
					cmSvc,
					aliasToSvc,
					certUpdateChan,
					certStatusRegistry,
				});
				epmgr.startHealthCheck(SYSTEM_CONFIG.healthCheckInterval.unwrap_or(300));
				epmgr.startCertUpdateListener();
				Ok(epmgr)
			}
			Err(e) => Err(e.to_string()),
		}
	}

	pub async fn IsValidDomain(&self, domain: &String) -> bool {
		let domainList = self.domains.read().await;
		if domainList.iter().any(|ns| ns.base == *domain) {
			true
		} else {
			warn!("didn't find a valid namespace for {}", domain);
			false
		}
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
	pub async fn NSIDToName(&self, id: &String) -> String {
		let domainList = self.domains.read().await;
		if let Some(name) = domainList.iter().find(|s| *s.id == *id) {
			name.base.clone()
		} else {
			warn!("didn't find a valid namespace for {}", id);
			"".to_string()
		}
	}
	pub async fn NSNameToID(&self, name: &String) -> String {
		let domainList = self.domains.read().await;
		if let Some(name) = domainList.iter().find(|s| *s.base == *name) {
			name.id.clone()
		} else {
			warn!("didn't find a valid namespace for {}", name);
			"".to_string()
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

	pub fn ServiceNameToID(&self, name: &String) -> Result<String, bool> {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(svcList) => {
				if let Some(service) = svcList.iter().find(|s| *s.name == *name) {
					Ok(service.id.clone())
				} else {
					Err(false)
				}
			}
			Err(_) => Err(false),
		}
	}
	pub async fn GetNSIDFromSvcID(&self, serviceID: &String) -> Option<String> {
		let domainList = self.domains.read().await;
		let nsList = domainList.clone();
		drop(domainList);
		for ns in nsList.iter() {
			if ns.services.iter().find(|svcID| *svcID == serviceID).is_some() {
				return Some(ns.id.clone());
			}
		}

		None
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
		let svcs = self.svcsList.try_lock();
		let epMap = self.epMap.try_lock();
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
				if let Some(eps) = m.get_mut(&format!("{}/{}", request.endpoint_name.clone(), request.service_name)) {
					debug!("added endpoint {} with hcr {}", format!("{}/{}", request.endpoint_name.clone(), request.service_name), &request.health_check_route);
					eps.push(RegisteredEndpoint {
						serviceName: request.service_name.clone(),
						address: request.endpoint.parse().unwrap(),
						healthCheckRoute: request.health_check_route.clone(),
						isExternalDevice: false,
						deviceID: None,
						epID: Some(Uuid::now_v7().to_string()),
						runningOnK8S: request.client_running_in_kubernetes,
					});
				} else {
					debug!("added new endpoint {} at {} with hcr {}", format!("{}/{}", request.endpoint_name.clone(), request.service_name), &request.endpoint, &request.health_check_route);
					m.insert(
						format!("{}/{}", request.endpoint_name.clone(), request.service_name),
						vec![RegisteredEndpoint {
							serviceName: request.service_name.clone(),
							address: request.endpoint.parse().unwrap(),
							healthCheckRoute: request.health_check_route.clone(),
							isExternalDevice: false,
							deviceID: None,
							epID: Some(Uuid::now_v7().to_string()),
							runningOnK8S: request.client_running_in_kubernetes,
						}],
					);
				}
			}
			Err(e) => {
				error!("RegisterServiceEndpoint TLE: {:?}", e);
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
					debug!("added endpoint {} to service {} with hcr {}", &endpoint, service_name, &format!("https://{}/ping", endpoint));
					eps.push(RegisteredEndpoint {
						serviceName: service_name.clone(),
						address: endpoint.parse().unwrap(),
						healthCheckRoute: format!("https://{}/ping", endpoint),
						isExternalDevice: true,
						deviceID: Some(deviceID),
						epID: None,
						runningOnK8S: false,
					});
				} else {
					debug!("added new endpoint {} at {} with hcr {}", &deviceID, &endpoint, format!("https://{}/ping", endpoint));
					m.insert(
						deviceID.clone(),
						vec![RegisteredEndpoint {
							serviceName: service_name.clone(),
							address: endpoint.parse().unwrap(),
							healthCheckRoute: format!("https://{}/ping", endpoint),
							isExternalDevice: true,
							deviceID: Some(deviceID),
							epID: None,
							runningOnK8S: false,
						}],
					);
				}
			}
			Err(e) => {
				error!("AddClientDeviceToPingerList TLE: {:?}", e);
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
						let mut rng = rand::rng();
						let idx = rng.random_range(0..eps.len() - 1);
						return Some(eps[idx].address.clone());
					} else if eps.len() != 0 {
						return Some(eps[0].address.clone());
					}
				}
				return None;
			}
			Err(e) => {
				error!("GetServiceEndpoint TLE: {:?}", e)
			}
		}
		None
	}
	pub(self) fn GetRegisteredEndpoints(&self, name: &String) -> Option<Vec<RegisteredEndpoint>> {
		let epMap = self.epMap.try_lock();
		match epMap {
			Ok(m) => {
				if let Some(eps) = m.get(name) {
					if eps.len() > 0 {
						return Some(eps.to_vec());
					}
				}
				//slow path
				for epName in m.keys() {
					if epName.contains(name) {
						if let Some(eps) = m.get(epName) {
							if eps.len() > 0 {
								return Some(eps.to_vec());
							}
						}
					}
				}

				return None;
			}
			Err(e) => {
				error!("GetServiceEndpoint TLE: {:?}", e)
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
			Err(e) => error!("RemoveServiceEndpoint TLE: {:?}", e),
		}
	}
	pub async fn NewService(&self, newSvc: &Service, nsName: &String) {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(mut svcList) => {
				if svcList.iter().find(|s| *s.name == *newSvc.name).is_none() {
					debug!("hi!");
					svcList.push(newSvc.clone());

					let mut nsList = self.domains.write().await;
					nsList.iter_mut().find(|ns| &ns.base == nsName).unwrap().services.push(newSvc.id.clone());
					drop(nsList);
				}
			}
			Err(e) => error!("AddServiceToKnownList TLE: {:?}", e),
		}
	}
	pub async fn RemoveNamesapce(&self, id: String) {
		let mut domainList = self.domains.write().await;
		domainList.remove_elem(|ns| ns.id == id);
	}
	pub fn RemoveService(&self, name: String) {
		let svcs = self.svcsList.try_lock();
		match svcs {
			Ok(mut svcList) => {
				svcList.remove_elem(|s| s.name == name);
			}
			Err(_) => {}
		}
	}
	fn startHealthCheck(self: &Arc<Self>, ttl: u64) {
		let hc = Arc::new(HealthChecker { client: Arc::clone(&self) });
		hc.StartHealthCheck(ttl);
	}
	fn startCertUpdateListener(self: &Arc<Self>) {
		let hc = Arc::new(CertChecker { client: Arc::clone(&self) });
		hc.StartCertCheck();
	}
}
impl CertChecker {
	pub fn StartCertCheck(self: &Arc<Self>) {
		let self_clone = Arc::clone(self);
		let mut cert_chan: Receiver<(ServiceCredentials, String)> = self_clone.client.certUpdateChan.clone();
		tokio::spawn(async move {
			loop {
				let certChanged = cert_chan.changed().await;
				if certChanged.is_ok() {
					let newCert = cert_chan.borrow_and_update().clone();
					if newCert.1 != "".to_string() {
						debug!("received cert update message for {}", newCert.1);
						match self_clone.client.GetRegisteredEndpoints(&newCert.1) {
							Some(eps) => {
								for rep in eps {
									let repName = rep.serviceName.clone();
									let mut sc: ServiceCredentials = newCert.0.clone().into();
									sc.id = Some(self_clone.client.ServiceNameToID(&repName).unwrap());
									self_clone.SendNewCredsToEP(rep, &sc).await;
								}
							}
							None => {
								debug!("no registered endpoints for {}", newCert.1)
							}
						}
					} else {
						error!("missing cert name");
					}
				} else {
					error!("cert_chan not ok: {:?}", certChanged.err())
				}
			}
		});
	}
	async fn SendNewCredsToEP(self: &Arc<Self>, rep: RegisteredEndpoint, newCreds: &ServiceCredentials) {
		let gkCert = self.client.cmSvc.GetExistingServiceCert("gatekeeper".to_string()).await.unwrap();
		let caChain: Vec<String> = gkCert.ca_cert.clone().split_inclusive("-----END CERTIFICATE-----").map(|s| s.to_string()).collect();
		let cert = X509::from_pem(&Bytes::from(gkCert.certificate.clone())).unwrap();
		let caInt = X509::from_pem(&Bytes::from(caChain[0].clone())).unwrap();
		let caRoot = X509::from_pem(&Bytes::from(caChain[1].clone())).unwrap();
		let pKey = PKey::private_key_from_pem(&Bytes::from(gkCert.private_key.clone())).unwrap();
		let value = Arc::new(CertKey::new(vec![cert], pKey));
		let connector = Connector::new(None);
		let addrParts = rep.healthCheckRoute.split("/").collect::<Vec<&str>>();
		let addr: SocketAddr = addrParts[2].to_string().parse().unwrap();
		let mut peer = HttpPeer::new(addr, true, rep.serviceName.clone());
		let mut peerOpts = PeerOptions::new();
		let hcr: Uri = rep.healthCheckRoute.replace("/ping", "/cert_renew").parse().unwrap();

		peer.client_cert_key = Some(value.clone());
		peerOpts.alpn = ALPN::H1;
		peerOpts.ca = Some(Arc::new(Box::new([caInt.clone(), caRoot.clone()])));
		peer.options = peerOpts;

		match connector.get_http_session(&peer).await {
			Ok((mut http, _reused)) => {
				let certJSON = serde_json::to_string(&newCreds).unwrap();
				let mut new_request = RequestHeader::build("POST", hcr.path().as_bytes(), None).unwrap();
				new_request.insert_header(header::HOST, rep.serviceName.clone()).unwrap();
				new_request.insert_header(header::CONTENT_LENGTH, certJSON.len()).unwrap();
				http.write_request_header(Box::new(new_request)).await.unwrap();

				let written = http.write_body(certJSON.as_bytes()).await;
				if written.is_err() {
					error!("{}", written.unwrap_err())
				}

				http.finish_body().await.unwrap();
				http.read_response().await.unwrap();
				let mut response_body = String::new();
				while let Some(chunk) = http.read_body_ref().await.unwrap() {
					response_body.push_str(&String::from_utf8_lossy(&chunk));
					if response_body != "ok" {
						let resp = response_body.clone();
						error!("cert propagation failed: {resp}");
						self.client
							.certStatusRegistry
							.SetStatus(
								CertUpdateResult { status: UpdateStatus::Failed { failureType: FailureType::Propagation, reason: resp }, timestamp: Utc::now().timestamp() },
								&rep.serviceName,
							)
							.await;
					} else {
						info!("propagation of new credentials successful for service {}", rep.serviceName)
					}
				}
			}
			Err(e) => error!("{}", e),
		}
	}
}
impl HealthChecker {
	pub fn StartHealthCheck(self: &Arc<Self>, healthCheckInterval: u64) {
		let self_clone = Arc::clone(self);
		tokio::spawn(async move {
			let gkCert = self_clone.client.cmSvc.GetExistingServiceCert("gatekeeper".to_string()).await.unwrap();
			let caChain: Vec<String> = gkCert.ca_cert.clone().split_inclusive("-----END CERTIFICATE-----").map(|s| s.to_string()).collect();

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
											new_request.insert_header("Host", rep.serviceName.clone()).unwrap();
											http.write_request_header(Box::new(new_request)).await.unwrap();
											http.finish_body().await.unwrap();
											http.read_response().await.unwrap();
											let mut response_body = String::new();
											while let Some(chunk) = http.read_body_ref().await.unwrap() {
												response_body.push_str(&String::from_utf8_lossy(&chunk));
											}

											if response_body != "pong" {
												if !rep.isExternalDevice {
													error!("incorrect response, adding endpoint '{key}' to removal list, received response: {}", response_body);
													to_remove.push(rep.epID.as_ref().unwrap().clone());
												} else {
													if let Some(devID) = &rep.deviceID {
														error!("incorrect response, adding device '{key}' to removal list, received response: {}", response_body);
														to_remove.push(devID.clone());
													}
												}
											} else {
												info!(target: "ep_monitor", event = "health_check", service = rep.serviceName, checkedAt = Utc::now().timestamp(), result = "success");
											}
										}
										Err(e) => {
											error!(
												"incorrect response, adding endpoint or device '{}' to removal list: {:?}",
												rep.epID.as_ref().unwrap_or(rep.deviceID.as_ref().unwrap_or(&"".to_string())),
												e
											);
											to_remove.push(rep.epID.as_ref().unwrap_or(rep.deviceID.as_ref().unwrap_or(&"".to_string())).clone());
										}
									}
								}
								for addr in to_remove {
									val.remove_elem(|e| {
										if e.isExternalDevice {
											return addr == *e.deviceID.as_ref().unwrap_or(&"".to_string());
										} else {
											*e.epID.as_ref().unwrap() == addr
										}
									});
								}
							}
						}
					}
					Err(e) => {
						error!("hc: {:?}", e)
					}
				}
			}
		});
	}
}
