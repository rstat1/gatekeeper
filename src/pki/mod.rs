/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

pub mod status_api;
pub mod supported_ca;

use crate::{
	cloudflare_api::CloudflareAPIClient,
	pki::{status_api::*, supported_ca::SupportedCA},
	services::v1::ServiceCredentials,
	vault::VaultClient,
	SYSTEM_CONFIG,
};
use base64::{alphabet, engine, engine::general_purpose, Engine};
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use instant_acme::{
	Account, AccountCredentials, AuthorizationStatus, BytesResponse, CertificateIdentifier, ChallengeType, HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RevocationReason,
	RevocationRequest,
};
use p384::{
	ecdsa::{signature::Verifier, *},
	SecretKey,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{
	runtime::Handle,
	sync::{
		watch::{channel, Receiver, Sender},
		RwLock,
	},
	time::sleep,
};
use tracing::{debug, error, info, warn};
use x509_parser::pem::parse_x509_pem;

struct ACMEHTTPClient;
struct ExpirationChecker {
	cmSvc: Arc<CertManagerSvc>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct NSCertificate {
	pub notAfter: i64,
	#[serde(rename = "name")]
	pub namespace: String,
	pub certChain: String,
	pub issuingCA: String,
	pub privateKey: String,
}
pub struct CertManagerSvc {
	devMode: bool,
	vault: Arc<VaultClient>,
	acmeContactEmail: String,
	cfAPI: Arc<CloudflareAPIClient>,
	certStatusReg: Arc<CertStatusRegistry>,
	nsCertCache: RwLock<HashMap<String, NSCertificate>>,
	certUpdateChannel: Sender<(ServiceCredentials, String)>,
	svcCertCache: RwLock<HashMap<String, ServiceCredentials>>,
}

impl ACMEHTTPClient {}
impl HttpClient for ACMEHTTPClient {
	fn request(&self, req: http::Request<Full<bytes::Bytes>>) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
		let (parts, mut body) = req.into_parts();
		let uri = parts.uri.to_string();
		let method = parts.method.clone();
		let headers = parts.headers.clone();

		Box::pin(async move {
			let client = reqwest::Client::new();
			let mut reqwest_req = client.request(method, &uri);

			for (key, value) in headers.iter() {
				reqwest_req = reqwest_req.header(key, value);
			}

			let body_frame = body.frame().await;
			if body_frame.is_some() {
				let body_bytes = body_frame.unwrap().unwrap().data_ref().unwrap().to_vec();
				reqwest_req = reqwest_req.body(body_bytes);
			}

			match client.execute(reqwest_req.build().unwrap()).await {
				Ok(rsp) => {
					let http_rsp: http::Response<reqwest::Body> = rsp.into();
					let bytes_rsp: BytesResponse = BytesResponse::from(http_rsp);
					Ok(bytes_rsp)
				}
				Err(e) => {
					error!("{}", e);
					Err(instant_acme::Error::from("error occured, see log"))
				}
			}
		})
	}
}
impl CertManagerSvc {
	pub async fn new(vault: Arc<VaultClient>, cfAPI: Arc<CloudflareAPIClient>, certStatusReg: Arc<CertStatusRegistry>) -> Result<(Arc<Self>, Receiver<(ServiceCredentials, String)>), String> {
		let mut nsCertCache: HashMap<String, NSCertificate> = HashMap::default();
		let mut svcCertCache: HashMap<String, ServiceCredentials> = HashMap::default();
		match vault.ListAllKeysAtKVPath("gatekeeper", Some("ns-certs")).await {
			Ok(keys) => {
				if let Some(knownCerts) = keys {
					let keysList = knownCerts.as_array();
					if let Some(keys) = keysList {
						for key in keys {
							match vault.ReadValueFromKV(format!("ns-certs/{}", key.as_str().unwrap()).as_str(), "gatekeeper").await {
								Ok(c) => {
									let cert: NSCertificate = serde_json::from_value(c).unwrap();
									certStatusReg
										.Add(RegisteredCertificate { issuedFor: cert.namespace.clone(), certType: CertificateType::Namespace })
										.await;
									nsCertCache.insert(key.as_str().unwrap().to_string(), cert);
								}
								Err(e) => {
									error!("{e}");
									return Err(e);
								}
							}
						}
					}
				}
			}
			Err(e) => {
				error!("checkCredentialCerts: {e}");
				return Err(e);
			}
		}
		match vault.ListAllKeysAtKVPath("gatekeeper-credentials", None).await {
			Ok(keys) => {
				if let Some(knownCerts) = keys {
					let keysList = knownCerts.as_array();
					if let Some(keys) = keysList {
						for key in keys {
							match vault.ReadValueFromKV(key.as_str().unwrap(), "gatekeeper-credentials").await {
								Ok(c) => {
									debug!("{}", key.as_str().unwrap());
									let cert: ServiceCredentials = serde_json::from_value(c).unwrap();
									certStatusReg
										.Add(RegisteredCertificate { issuedFor: key.as_str().unwrap().to_string(), certType: CertificateType::Endpoint })
										.await;
									svcCertCache.insert(key.as_str().unwrap().to_string(), cert);
								}
								Err(e) => {
									error!("{e}");
									return Err(e);
								}
							}
						}
					}
				} else {
					debug!("no knownCerts");
				}
			}
			Err(e) => {
				error!("checkCredentialCertss: {e}");
				return Err(e);
			}
		}

		let (certUpdateChannel, recv) = channel((ServiceCredentials::default(), "".to_string()));
		let cmSvc = Arc::new(Self {
			vault,
			cfAPI,
			devMode: SYSTEM_CONFIG.devMode.unwrap_or(false),
			acmeContactEmail: SYSTEM_CONFIG.acmeContactEmail.clone(),
			nsCertCache: RwLock::new(nsCertCache),
			certUpdateChannel,
			certStatusReg,
			svcCertCache: RwLock::new(svcCertCache),
		});
		cmSvc.startExpireChecker(SYSTEM_CONFIG.certCheckInterval.unwrap_or(3600).into());
		Ok((cmSvc, recv))
	}
	pub async fn GenerateServiceCert(&self, serviceName: &String) -> Result<ServiceCredentials, String> {
		let certResult = self.vault.GenerateServiceCert("gatekeeper", &serviceName).await;
		match certResult {
			Ok(cert) => {
				let certToSave = cert.clone();
				let sc: ServiceCredentials = certToSave.into();

				let mut certCache = self.svcCertCache.write().await;
				if certCache.contains_key(serviceName) {
					if let Some(existing) = certCache.get_mut(serviceName) {
						*existing = sc.clone();
						drop(certCache);
					}
				} else {
					certCache.insert(serviceName.clone(), sc.clone());
					drop(certCache);
				}

				self.vault.WriteStructToKV(&serviceName.as_str(), "gatekeeper-credentials", &sc).await?;

				Ok(sc)
			}
			Err(e) => Err(e),
		}
	}
	pub async fn GenerateACMECert(&self, namespace: &String, nsID: &String, certID: Option<CertificateIdentifier<'_>>) -> Result<bool, String> {
		let renewTime: i64;
		let privateKey: String;
		let mut ids = Vec::default();
		let mut dnsRecordID: String = String::default();

		let (account, issuingCA) = match self.getACMEAccount().await {
			Ok(a) => a,
			Err(e) => return Err(e),
		};

		info!("requesting certs for {namespace} using {issuingCA}");

		ids.push(Identifier::Dns(namespace.to_string()));
		ids.push(Identifier::Dns(format!("*.{namespace}")));
		let mut newOrder = NewOrder::new(ids.as_slice());

		if certID.is_some() {
			newOrder = newOrder.replaces(certID.unwrap());
		}

		match account.new_order(&newOrder).await {
			Ok(mut order) => {
				let mut authorizations = order.authorizations();
				while let Some(result) = authorizations.next().await {
					let mut authz = result.unwrap();
					match authz.status {
						AuthorizationStatus::Pending => {}
						AuthorizationStatus::Valid => continue,
						_ => todo!(),
					}

					let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| "no dns01 challenge found")?;
					let txtRecordNS = format!("_acme-challenge.{}", namespace);
					dnsRecordID = self.cfAPI.CreateNewTXTRecord(&txtRecordNS, challenge.key_authorization().dns_value(), "Created by Gatekeeper").await?;
					sleep(Duration::from_secs(10)).await;
					info!("that was a good nap, resuming cert request process...");
					match challenge.set_ready().await {
						Ok(_) => {}
						Err(e) => {
							return Err(e.to_string());
						}
					}
				}
				let status = order.poll(5, Duration::from_millis(250)).await.unwrap();
				if status != OrderStatus::Ready {
					return Err("unexpected order status: {status:?}".to_string());
				}

				let key = order.finalize().await;
				if key.is_ok() {
					privateKey = key.unwrap();
				} else {
					return Err(key.unwrap_err().to_string());
				}

				let certChain = loop {
					match order.certificate().await.unwrap() {
						Some(cert_chain_pem) => break cert_chain_pem,
						None => sleep(Duration::from_secs(1)).await,
					}
				};

				let certDer: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certChain.as_bytes()).map(|result| result.unwrap()).collect();
				let certID = CertificateIdentifier::try_from(certDer.first().unwrap());
				if certID.is_ok() {
					let cid = certID.unwrap();
					match account.renewal_info(&cid).await {
						Ok(ri) => {
							debug!("{:?}", ri);
							renewTime = StdRng::from_os_rng().random_range(ri.suggested_window.start.unix_timestamp()..=ri.suggested_window.end.unix_timestamp());
						}
						Err(e) => return Err(e.to_string()),
					}
				} else {
					return Err(certID.unwrap_err().to_string());
				}

				let newCert = NSCertificate { certChain, privateKey, notAfter: renewTime, issuingCA, namespace: namespace.to_string() };
				let r = self.vault.WriteStructToKV(format!("ns-certs/{}", nsID).as_str(), "gatekeeper", &newCert).await;
				if r.is_err() {
					return Err(r.unwrap_err());
				}
				let mut certCache = self.nsCertCache.write().await;

				if certCache.contains_key(&namespace.to_string()) {
					if let Some(existing) = certCache.get_mut(namespace) {
						*existing = newCert;
					}
				} else {
					certCache.insert(namespace.to_string(), newCert);
					self.certStatusReg
						.Add(RegisteredCertificate { issuedFor: namespace.to_string(), certType: CertificateType::Endpoint })
						.await;
				}
				drop(certCache);

				if dnsRecordID != "" {
					self.cfAPI.DeleteDNSRecord(&dnsRecordID).await?;
					debug!("cleaned up dns records");
				}
			}
			Err(e) => return Err(format!("GenerateACMECert(order): {}", e)),
		}
		Ok(true)
	}
	pub async fn GetCachedNSCert(&self, ns: String) -> Option<NSCertificate> {
		debug!("get cert for {ns}");
		let certs = self.nsCertCache.read().await;
		certs.get(&ns).cloned()
	}
	pub async fn IsCertCacheEmpty(&self) -> bool {
		let certs = self.nsCertCache.read().await;
		certs.len() == 0
	}
	pub async fn GetExistingServiceCert(&self, serviceName: String) -> Option<ServiceCredentials> {
		let certs = self.svcCertCache.read().await;
		let c = certs.get(&serviceName).cloned();
		drop(certs);

		c
	}
	pub fn GetExistingServiceCertBlocking(&self, serviceName: String) -> Option<ServiceCredentials> {
		tokio::task::block_in_place(move || {
			Handle::current().block_on(async move {
				debug!("get creds...");
				self.GetExistingServiceCert(serviceName).await
			})
		})
	}
	pub async fn SignWithGatekeeperCert(&self, toSign: String) -> Result<String, String> {
		match self.GetExistingServiceCert("gatekeeper".to_string()).await {
			Some(c) => {
				let key = SecretKey::from_sec1_pem(&c.private_key.as_str()).unwrap();
				let sk = SigningKey::from(key);

				match sk.sign_recoverable(toSign.as_bytes()) {
					Ok(sig) => Ok(engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD).encode(sig.0.to_der().as_bytes())),
					Err(e) => Err(e.to_string()),
				}
			}
			None => Err("couldn't retrieve gatekeeper cert".to_string()),
		}
	}
	pub async fn VerifySignature(&self, serviceName: String, message: &String, msgSig: &String) -> Result<bool, String> {
		if serviceName.is_empty() || message.is_empty() || msgSig.is_empty() {
			return Err("one or more invalid arguments provided".to_string());
		}

		match self.GetExistingServiceCert(serviceName).await {
			Some(c) => match parse_x509_pem(c.certificate.as_bytes()) {
				Ok(cert) => match cert.1.parse_x509() {
					Ok(parsed) => {
						let sigDecoded = engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD).decode(msgSig.clone()).unwrap();
						let pk = &parsed.tbs_certificate.public_key().subject_public_key;
						let sig = Signature::from_der(&sigDecoded).unwrap();

						match VerifyingKey::from_sec1_bytes(&pk.data) {
							Ok(r) => match r.verify(&message.as_bytes(), &sig) {
								Ok(_) => Ok(true),
								Err(e) => Err(format!("Verify failed: {:?}", e)),
							},
							Err(e) => Err(format!("error processing public key: {}", e.to_string())),
						}
					}
					Err(e) => Err(format!("X509CertParsing error: {}", e.to_string())),
				},
				Err(e) => Err(format!("Pem error: {}", e.to_string())),
			},
			None => Err(format!("GetExistingServiceCert error: couldn't retrieve cert")),
		}
	}
	pub async fn IsCertificateExpired(&self, serviceName: &String) -> Result<bool, String> {
		match self.GetExistingServiceCert(serviceName.clone()).await {
			Some(c) => {
				let certExpireTime: i64 = c.expires_at.try_into().unwrap_or(0);
				let mut currentTime = Utc::now();

				debug!("service name: {serviceName}");
				for _ in 1..6 {
					currentTime = currentTime.checked_add_days(chrono::Days::new(1)).unwrap();
					debug!("current time: {}, certExpireTime: {certExpireTime}", currentTime.timestamp());
					if currentTime.timestamp() >= certExpireTime {
						return Ok(true);
					}
				}

				Ok(false)
			}
			None => Err(format!("GetExistingServiceCert error: couldn't retrieve cert")),
		}
	}
	pub async fn RevokeServiceCert(&self, serviceName: &String) -> Result<(), String> {
		match self.GetExistingServiceCert(serviceName.clone()).await {
			Some(cert) => {
				if cert.private_key == "".to_string() {
					warn!("this operation will fail without a private key");
				}

				let revokeResult = self.vault.RevokeServiceCert(cert.certificate, cert.private_key).await;
				if revokeResult.is_ok() {
					let delResult = self.vault.DeleteKVPair(&serviceName, "gatekeeper-credentials").await;
					if delResult.is_ok() {
						let mut certs = self.svcCertCache.write().await;
						certs.remove(serviceName);
						drop(certs);
						self.certStatusReg.Remove(serviceName).await;
						return Ok(());
					} else {
						return Err(delResult.unwrap_err());
					}
				} else {
					Err(revokeResult.unwrap_err())
				}
			}
			None => Err(format!("GetExistingServiceCert error: couldn't retrieve cert")),
		}
	}
	pub async fn RevokeNSCert(&self, nsID: &String) -> Result<(), String> {
		match self.vault.ReadValueFromKV(format!("ns-certs/{nsID}").as_str(), "gatekeeper").await {
			Ok(c) => {
				let cert: NSCertificate = serde_json::from_value(c).unwrap();
				match self.getACMEAccountForCA(&cert.issuingCA).await {
					Ok(acc) => {
						let firstCert: Vec<&str> = cert.certChain.split_inclusive("-----END CERTIFICATE-----").collect();
						let derCert = CertificateDer::from_pem_slice(firstCert[0].as_bytes()).unwrap();

						match acc.revoke(&RevocationRequest { certificate: &derCert, reason: Some(RevocationReason::CessationOfOperation) }).await {
							Ok(()) => match self.vault.DeleteKVPair(format!("ns-certs/{nsID}").as_str(), "gatekeeper").await {
								Ok(()) => {
									let mut certs = self.nsCertCache.write().await;
									certs.remove(nsID);
									return Ok(());
								}
								Err(e) => return Err(e),
							},
							Err(e) => {
								error!("RevokeNSCert: error occured during certificate revocation: {e}");
								return Err(e.to_string());
							}
						}
					}
					Err(e) => {
						error!("RevokeNSCert: error occured during account retrival: {e}");
						return Err(e.to_string());
					}
				}
			}
			Err(e) => {
				error!("RevokeNSCert: error occured during cert retrival: {e}");
				return Err(e);
			}
		}
	}
	async fn getACMEAccount(&self) -> Result<(Account, String), String> {
		let useGTS = StdRng::from_os_rng().random_ratio(1, 2);
		let (ca, credsPath) = if self.devMode {
			if useGTS {
				let credentials = self.getGCPCredentials().await?;
				(SupportedCA::GoogleTrustServices { staging: true, credentials }, "ca-creds-gts-stg")
			} else {
				(SupportedCA::LetsEncrypt { staging: true }, "ca-creds-letsencrypt-stg")
			}
		} else {
			if useGTS {
				let credentials = self.getGCPCredentials().await?;
				(SupportedCA::GoogleTrustServices { staging: false, credentials }, "ca-creds-gts")
			} else {
				(SupportedCA::LetsEncrypt { staging: false }, "ca-creds-letsencrypt")
			}
		};
		debug!("looking up account at {credsPath}");
		match self.vault.ReadValueFromKV(credsPath, "gatekeeper").await {
			Ok(credsStr) => {
				let ac: AccountCredentials = serde_json::from_str(credsStr["credentials"].as_str().unwrap()).unwrap();
				Ok((Account::from_credentials_and_http(ac, Box::new(ACMEHTTPClient {})).await.unwrap(), ca.name().to_string()))
			}
			Err(_) => Ok((self.createACMEAccount(&ca).await?.0, ca.name().to_string())),
		}
	}
	async fn getACMEAccountForCA(&self, caName: &String) -> Result<Account, String> {
		match self.vault.ReadValueFromKV(format!("ca-creds-{}", &caName).as_str(), "gatekeeper").await {
			Ok(account) => {
				let ac: AccountCredentials = serde_json::from_str(account["credentials"].as_str().unwrap()).unwrap();
				Ok(Account::from_credentials_and_http(ac, Box::new(ACMEHTTPClient {})).await.unwrap())
			}
			Err(e) => Err(e),
		}
	}
	async fn getGCPCredentials(&self) -> Result<String, String> {
		self.vault.ReadValueFromKV("gcp-service-account", "gatekeeper").await.map(|c| {
			let v: Value = serde_json::from_value(c).unwrap();
			let key_decoded = engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD)
				.decode(v["credential"].as_str().unwrap())
				.unwrap();
			String::from_utf8(key_decoded).unwrap()
		})
	}
	async fn createACMEAccount(&self, ca: &SupportedCA) -> Result<(Account, AccountCredentials), String> {
		let mut extAcc: Option<instant_acme::ExternalAccountKey> = None;
		if ca.requires_eab() {
			let eabMaker = ca.get_eak_creator().unwrap();
			match eabMaker.GetExternalAccountKey().await {
				Ok(acc) => extAcc = Some(acc),
				Err(e) => {
					error!("{e}");
					return Err(e);
				}
			}
		}
		match Account::create_with_http(
			&NewAccount { contact: &[format!("mailto:{}", self.acmeContactEmail).as_str()], terms_of_service_agreed: true, only_return_existing: false },
			ca.url().to_string(),
			extAcc.as_ref(),
			Box::new(ACMEHTTPClient {}),
		)
		.await
		{
			Ok(r) => {
				let credsJSON = serde_json::to_string(&r.1).unwrap();
				self.vault
					.WriteValueToKV(format!("ca-creds-{}", ca.name()).as_str(), "credentials", credsJSON.as_str(), "gatekeeper")
					.await?;

				Ok(r)
			}
			Err(e) => {
				error!("{e}");
				Err(e.to_string())
			}
		}
	}
	fn startExpireChecker(self: &Arc<Self>, checkIntervalSecs: u64) {
		let hc = Arc::new(ExpirationChecker { cmSvc: Arc::clone(&self) });
		hc.Start(checkIntervalSecs);
	}
}
impl ExpirationChecker {
	pub fn Start(self: &Arc<Self>, checkIntervalSecs: u64) {
		let self_clone = Arc::clone(self);
		tokio::spawn(async move {
			loop {
				info!("starting expiry check. Running every {} minutes", checkIntervalSecs / 60);
				if !self_clone.cmSvc.IsCertCacheEmpty().await {
					self_clone.checkNSCerts().await;
					self_clone.checkCredentialCerts().await;
					info!("Ok, sleep time. Hey google set an alarm for {} minutes", checkIntervalSecs / 60);
				} else {
					warn!("cert cache empty");
				}
				tokio::time::sleep(Duration::from_secs(checkIntervalSecs)).await;
			}
		});
	}
	async fn checkCredentialCerts(self: &Arc<Self>) {
		let svcCerts = self.cmSvc.svcCertCache.read().await;
		let svcCertsList = svcCerts.clone();
		drop(svcCerts);
		for svcc in svcCertsList.iter() {
			match self.cmSvc.IsCertificateExpired(&svcc.0).await {
				Ok(wellIsIt) => {
					if wellIsIt {
						debug!("generate new cert for {}", &svcc.0);
						match self.cmSvc.GenerateServiceCert(&svcc.0).await {
							Ok(newCert) => {
								if *svcc.0 == "gatekeeper".to_string() {
									match std::fs::write("certs/gkcert.pem", format!("{}\n{}", &newCert.certificate, &newCert.private_key)) {
										Ok(_) => {}
										Err(e) => panic!("failed to write gk cert to disk: {}", e.to_string()),
									}
									match std::fs::write("certs/gkroot.pem", &newCert.ca_cert) {
										Ok(_) => {}
										Err(e) => panic!("failed to write gk cert to disk: {}", e.to_string()),
									}
								}
								self.cmSvc.certUpdateChannel.send_replace((newCert, svcc.0.clone()));
							}
							Err(e) => {
								self.cmSvc
									.certStatusReg
									.SetStatus(
										CertUpdateResult { status: UpdateStatus::Failed { failureType: FailureType::Generation, reason: e }, timestamp: Utc::now().timestamp() },
										&svcc.0,
									)
									.await;
							}
						}
					}
				}
				Err(e) => error!("checkCredentialCerts: {e}"),
			}
		}
	}
	async fn checkNSCerts(self: &Arc<Self>) {
		let nsCerts = self.cmSvc.nsCertCache.read().await;
		for nsc in nsCerts.iter() {
			let expireTime = nsc.1.notAfter;
			let mut currentTime = Utc::now();
			debug!("namespace: {}", nsc.0);
			for _ in 1..6 {
				currentTime = currentTime.checked_add_days(chrono::Days::new(1)).unwrap();
				debug!("current time: {}, certExpireTime: {expireTime}", currentTime.timestamp());
				if currentTime.timestamp() >= expireTime {
					let certDer: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(nsc.1.certChain.as_bytes()).map(|result| result.unwrap()).collect();
					let certID = CertificateIdentifier::try_from(certDer.first().unwrap());
					if certID.is_ok() {
						match self.cmSvc.GenerateACMECert(&nsc.1.namespace, &nsc.0, Some(certID.unwrap())).await {
							Ok(_) => {
								self.cmSvc
									.certStatusReg
									.SetStatus(CertUpdateResult { status: UpdateStatus::Success, timestamp: currentTime.timestamp() /*  */ }, &nsc.1.namespace)
									.await;
							}
							Err(e) => {
								self.cmSvc
									.certStatusReg
									.SetStatus(
										CertUpdateResult { status: UpdateStatus::Failed { failureType: FailureType::Generation, reason: e }, timestamp: currentTime.timestamp() },
										&nsc.1.namespace,
									)
									.await;
							}
						}
					}
				}
			}
		}
	}
}
impl std::fmt::Debug for CertManagerSvc {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "nothing to see here")
	}
}
