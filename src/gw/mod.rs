/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]
#![allow(unused)]

use http::Uri;
use pingora::tls::{pkey::PKey, ssl::NameType, x509::X509};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tonic::async_trait;
use tracing::{debug, error};

use crate::{
	data::DataStore,
	services::endpoint_manager::EndpointManagerImpl,
	services::v1::{Alias, Service},
	vault::Certificate,
};

const DEVICE_API_CONTENT_TYPE: &str = "application/x-gatekeeper-device-api";

pub mod grpc_transcoder;
pub mod reverse_proxy;

pub struct DynamicCert;
pub struct ReverseProxy {
	grpcCert: Certificate,
	staticFileServerAddr: String,
	deviceAuthServerAddr: String,
	epMgr: Arc<EndpointManagerImpl>,
}

impl ReverseProxy {
	pub fn new(epMgr: Arc<EndpointManagerImpl>, staticFileServerAddr: &String, gkCert: &Certificate, deviceAuthServerAddr: &String) -> Self {
		ReverseProxy { epMgr, staticFileServerAddr: staticFileServerAddr.clone(), grpcCert: gkCert.clone(), deviceAuthServerAddr: deviceAuthServerAddr.clone() }
	}
}

impl DynamicCert {
	pub fn new() -> Box<Self> {
		Box::new(DynamicCert {})
	}
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
	async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
		use pingora::tls::ext;
		let serverName = ssl.servername(NameType::HOST_NAME);

		if let Some(serverName) = serverName {
			let url: Uri = serverName.parse().unwrap();
			let urlParts: Vec<&str> = url.host().unwrap().split(".").collect();
			let base = url.to_string().replace(urlParts[0], "").replacen(".", "", 1);

			let certPathStr = format!("certs/{}.crt", base);
			let certKeyStr = format!("certs/{}.key", base);

			let certPath = Path::new(certPathStr.as_str());
			let certKey = Path::new(certKeyStr.as_str());

			if certPath.exists() && certKey.exists() {
				let cert_bytes = std::fs::read(certPath).unwrap();
				let key_bytes = std::fs::read(certKey).unwrap();
				let key = PKey::private_key_from_pem(&key_bytes).unwrap();

				ext::ssl_use_private_key(ssl, &key).unwrap();

				match X509::stack_from_pem(&cert_bytes) {
					Ok(certs) => {
						debug!("cert stack len = {}", certs.len());
						debug!("{:?}", certs[0].subject_name());

						ext::ssl_use_certificate(ssl, &certs[0]).unwrap();

						if certs.len() > 1 {
							debug!("{:?}", certs[1].subject_name());
							if let Err(e) = ext::ssl_add_chain_cert(ssl, &certs[1]) {
								error!("ssl_add_chain_cert returned: {}", e);
							}
						} else {
							let caCertPath = Path::new("certs/e6.crt");
							let ca_bytes = std::fs::read(caCertPath).unwrap();
							let caCert = X509::from_pem(&ca_bytes).unwrap();

							if let Err(e) = ext::ssl_add_chain_cert(ssl, &caCert) {
								error!("ssl_add_chain_cert returned: {}", e);
							}
						}
					}
					Err(errs) => {
						error!("{:?}", errs);
					}
				}
			}
		}
	}
}
