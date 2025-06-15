/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use base64::{alphabet, engine, engine::general_purpose, Engine};
use google_cloud_auth::credentials::{service_account::Builder, Credentials};
use google_cloud_security_publicca_v1::client::PublicCertificateAuthorityService;
use google_cloud_security_publicca_v1::model::ExternalAccountKey;

#[async_trait::async_trait]
pub trait ExternalAccountKeyFetcher: Send {
	async fn GetExternalAccountKey(&self) -> Result<instant_acme::ExternalAccountKey, String>;
}

#[derive(Default)]
pub struct DefaultEAKCreator;

#[async_trait::async_trait]
impl ExternalAccountKeyFetcher for DefaultEAKCreator {
	async fn GetExternalAccountKey(&self) -> Result<instant_acme::ExternalAccountKey, String> {
		todo!()
	}
}

#[derive(Default)]
pub struct GoogleTrustServicesEAKCreator {
	staging: bool,
	service_account: String,
}

impl GoogleTrustServicesEAKCreator {
	pub fn new(service_account: String, staging: bool) -> Self {
		GoogleTrustServicesEAKCreator { service_account, staging }
	}
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Default, Clone)]
struct ServiceAccountKey {
	/// The client email address of the service account.
	/// (e.g., "my-sa@my-project.iam.gserviceaccount.com").
	client_email: String,
	/// ID of the service account's private key.
	private_key_id: String,
	/// The PEM-encoded PKCS#8 private key string associated with the service account.
	/// Begins with `-----BEGIN PRIVATE KEY-----`.
	private_key: String,
	/// The project id the service account belongs to.
	project_id: String,
	/// The universe domain this service account belongs to.
	universe_domain: Option<String>,
}

#[async_trait::async_trait]
impl ExternalAccountKeyFetcher for GoogleTrustServicesEAKCreator {
	async fn GetExternalAccountKey(&self) -> Result<instant_acme::ExternalAccountKey, String> {
		let mut ep = "https://publicca.googleapis.com";

		if self.staging {
			ep = "https://preprod-publicca.googleapis.com";
		}

		let sak: ServiceAccountKey = serde_json::from_str(&self.service_account).unwrap();
		let creds: Credentials = Builder::new(serde_json::from_str(&self.service_account.as_str()).unwrap()).build().unwrap();
		let client = PublicCertificateAuthorityService::builder().with_endpoint(ep).with_credentials(creds).build().await.unwrap();

		let r = client
			.create_external_account_key()
			.set_external_account_key(ExternalAccountKey::default())
			.set_parent(format!("projects/{}/locations/global", sak.project_id))
			.send()
			.await;
		match r {
			Ok(r) => {
				let key_decoded = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).decode(&r.b64_mac_key);
				Ok(instant_acme::ExternalAccountKey::new(r.key_id, &key_decoded.unwrap()))
			}
			Err(e) => Err(e.to_string()),
		}
	}
}

pub enum SupportedCA {
	LetsEncrypt { staging: bool },
	GoogleTrustServices { staging: bool, credentials: String },
}

impl SupportedCA {
	pub fn name(&self) -> &'static str {
		match self {
			SupportedCA::LetsEncrypt { staging } => {
				if *staging {
					"letsencrypt-stg"
				} else {
					"letsencrypt"
				}
			}
			SupportedCA::GoogleTrustServices { staging, credentials: _ } => {
				if *staging {
					"gts-stg"
				} else {
					"gts"
				}
			}
		}
	}
	pub fn url(&self) -> &'static str {
		match self {
			SupportedCA::LetsEncrypt { staging } => {
				if *staging {
					"https://acme-staging-v02.api.letsencrypt.org/directory"
				} else {
					"https://acme-v02.api.letsencrypt.org/directory"
				}
			}
			SupportedCA::GoogleTrustServices { staging, credentials: _ } => {
				if *staging {
					"https://dv.acme-v02.test-api.pki.goog/directory"
				} else {
					"https://dv.acme-v02.api.pki.goog/directory"
				}
			}
		}
	}
	pub fn requires_eab(&self) -> bool {
		match self {
			SupportedCA::LetsEncrypt { staging: _ } => false,
			SupportedCA::GoogleTrustServices { staging: _, credentials: _ } => true,
		}
	}
	pub fn get_eak_creator(&self) -> Option<Box<dyn ExternalAccountKeyFetcher>> {
		match self {
			SupportedCA::LetsEncrypt { .. } => None,
			SupportedCA::GoogleTrustServices { staging, credentials } => Some(Box::new(GoogleTrustServicesEAKCreator::new(credentials.clone(), *staging))),
		}
	}
}
