/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use base64::{alphabet, engine, engine::general_purpose, Engine};
use http_body_util::{BodyExt, Full};
use instant_acme::{Account, AccountCredentials, BytesResponse, ChallengeType, ExternalAccountKey, HttpClient, Identifier, NewAccount, NewOrder};
use p384::{
	ecdsa::{signature::Verifier, *},
	SecretKey,
};
use std::{error::Error, future::Future, path::Path, pin::Pin, sync::Arc};
use tracing::{debug, error, info};
use x509_parser::pem::parse_x509_pem;

use crate::vault::{Certificate, VaultClient};

pub struct CertManagerSvc {
	vault: Arc<VaultClient>,
}

struct ACMEHTTPClient;
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
	pub async fn new(vault: Arc<VaultClient>) -> Result<Self, String> {
		Ok(Self { vault })
		// match vault.ReadValueFromKV("internalsvcca_eab").await {
		// 	Ok(eab) => {
		// 		let creds: EABCreds = serde_json::from_str(eab["creds"].as_str().unwrap()).map_err(|e| String::from(e.to_string()))?;
		// 		Ok(Self { creds, vaultACMEEndpoint: vaultACMEEndpoint.clone(), vault })
		// 	}
		// 	Err(_) => match vault.GetEABCreds().await {
		// 		Ok(creds) => {
		// 			let credStr: String = serde_json::to_string(&creds).unwrap();
		// 			match vault.WriteValueToKV("internalsvcca_eab", "creds", credStr).await {
		// 				Ok(_) => Ok(Self { creds, vaultACMEEndpoint: vaultACMEEndpoint.clone(), vault: vault }),
		// 				Err(e) => Err(e),
		// 			}
		// 		}
		// 		Err(e) => Err(e),
		// 	},
		// }
	}
	pub async fn GenerateServiceCert(&self, serviceName: &String) -> Result<Certificate, String> {
		let certResult = self.vault.GenerateServiceCert("gatekeeper", &serviceName).await;
		match certResult {
			Ok(cert) => {
				let mut certToSave = cert.clone();
				if serviceName != &"gatekeeper".to_string() {
					certToSave.private_key = "".to_string();
				}
				let certJSON = serde_json::to_string(&certToSave).unwrap();
				let er = self.vault.Encrypt("platform", certJSON.as_str()).await?;
				match std::fs::write(format!("certs/svcs/{}.cert", serviceName), er.ciphertext) {
					Ok(_) => Ok(cert),
					Err(e) => Err(e.to_string()),
				}
			}
			Err(e) => Err(e),
		}
	}
	pub async fn GetExistingServiceCert(&self, serviceName: String) -> Result<Certificate, String> {
		let certPathStr = format!("certs/svcs/{}.cert", serviceName);
		let certPath = Path::new(certPathStr.as_str());
		if certPath.exists() {
			let conf_file = std::fs::read_to_string(certPath);
			match conf_file {
				Ok(file) => match self.vault.Decrypt("platform", file.as_str()).await {
					Ok(r) => {
						let key_decoded = engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD).decode(r.plaintext).unwrap();
						Ok::<Certificate, String>(serde_json::from_slice(&key_decoded).unwrap())
					}
					Err(e) => Err(e),
				},
				Err(e) => panic!("{:?}", e),
			}
		} else {
			Err(format!("cert for service {} does not exist", serviceName))
		}
	}
	pub async fn SignWithGatekeeperCert(&self, toSign: String) -> Result<String, String> {
		match self.GetExistingServiceCert("gatekeeper".to_string()).await {
			Ok(c) => {
				let key = SecretKey::from_sec1_pem(&c.private_key.as_str()).unwrap();
				let sk = SigningKey::from(key);

				match sk.sign_recoverable(toSign.as_bytes()) {
					Ok(sig) => Ok(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(sig.0.to_der().as_bytes())),
					Err(e) => Err(e.to_string()),
				}
			}
			Err(e) => Err(e),
		}
	}
	pub async fn VerifyMessage(&self, serviceName: String, message: String, msgSig: String) -> Result<bool, String> {
		if serviceName.is_empty() || message.is_empty() || msgSig.is_empty() {
			return Err("one or more invalid arguments provided".to_string());
		}

		match self.GetExistingServiceCert(serviceName).await {
			Ok(c) => match parse_x509_pem(c.certificate.as_bytes()) {
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
			Err(e) => Err(format!("GetExistingServiceCert error: {e}")),
		}
	}
	pub async fn GenerateACMECert(&self, serviceName: &String) -> Result<bool, String> {
		let account: Account;

		let r = self.vault.ReadValueFromKV("internalsvcca_account").await;
		if r.is_ok() {
			let credStr: serde_json::Value = serde_json::from_value(r.unwrap()).unwrap();
			let ac: AccountCredentials = serde_json::from_str(credStr["creds"].as_str().unwrap()).unwrap();
			account = Account::from_credentials_and_http(ac, Box::new(ACMEHTTPClient {})).await.unwrap()
		} else {
			let key_decoded = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).decode("&self.creds.key".to_string()).unwrap();
			let res = Account::create_with_http(
				&NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false },
				"&self.vaultACMEEndpoint",
				Some(&ExternalAccountKey::new("self.creds.id".to_string(), &key_decoded)),
				Box::new(ACMEHTTPClient {}),
			)
			.await;
			match res {
				Ok(acc) => {
					account = acc.0;
					let creds = serde_json::to_value(acc.1).map_err(|e| e.to_string())?;
					match self.vault.WriteValueToKV("internalsvcca_account", "creds", creds.to_string()).await {
						Ok(_) => {}
						Err(e) => return Err(e),
					}
					info!("account created: {:#?}", account.id());
				}
				Err(e) => {
					tracing::error!("{}, {:?}", e, e.source());
					return Err(e.to_string());
				}
			}
		}

		let mut order = account
			.new_order(&NewOrder { identifiers: &Vec::from([Identifier::Dns(serviceName.clone())]) })
			.await
			.map_err(|e| String::from(e.to_string()))?;

		let state = order.state();
		info!("order state: {:#?}", state);
		let auths = order.authorizations().await.map_err(|w| w.to_string())?;

		for a in auths {
			let challenge = a.challenges.iter().find(|c| c.r#type == ChallengeType::Http01).unwrap();
			debug!("{:?}", order.key_authorization(challenge).as_str());
			// order.key_authorization(challenge).digest();
			// let _ = order.challenge(&challenge.url).await;
			let _ = order.set_challenge_ready(&challenge.url).await;
		}

		Ok(true)
	}
}
