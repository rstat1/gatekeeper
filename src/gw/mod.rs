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
use tracing::{debug, error, info};

use crate::{
	data::DataStore,
	pki::CertManagerSvc,
	services::{
		endpoint_manager::EndpointManagerImpl,
		v1::{Alias, Service},
	},
	vault::{Certificate, VaultClient},
};

const DEVICE_API_CONTENT_TYPE: &str = "application/x-gatekeeper-device-api";

pub mod grpc_transcoder;
pub mod reverse_proxy;

pub struct DynamicCert {
	cmSvc: Arc<CertManagerSvc>,
}
pub struct ReverseProxy {
	grpcCert: Certificate,
	staticFileServerAddr: String,
	deviceAuthServerAddr: String,
	epMgr: Arc<EndpointManagerImpl>,
}

impl ReverseProxy {
	pub fn new(epMgr: Arc<EndpointManagerImpl>, staticFileServerAddr: &String, gkCert: &Certificate, deviceAuthServerAddr: &String) -> Self {
		info!("gw init");
		ReverseProxy { epMgr, staticFileServerAddr: staticFileServerAddr.clone(), grpcCert: gkCert.clone(), deviceAuthServerAddr: deviceAuthServerAddr.clone() }
	}
}

impl DynamicCert {
	pub fn new(cmSvc: Arc<CertManagerSvc>) -> Box<Self> {
		Box::new(DynamicCert { cmSvc })
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
			let cert = self.cmSvc.GetCachedNSCert(base).await;

			if let Some(nsCert) = cert {
				debug!("got cert");
				let cert_bytes = nsCert.certChain.as_bytes();
				let key_bytes = nsCert.privateKey.as_bytes();
				let key = PKey::private_key_from_pem(&key_bytes).unwrap();

				ext::ssl_use_private_key(ssl, &key).unwrap();

				match X509::stack_from_pem(&cert_bytes) {
					Ok(certs) => {
						if certs.len() > 1 {
							for i in 0..certs.len() {
								if i == 0 {
									ext::ssl_use_certificate(ssl, &certs[i]).unwrap();
								}
								if i > 0 {
									debug!("{:?}", certs[i].subject_name());
									if let Err(e) = ext::ssl_add_chain_cert(ssl, &certs[i]) {
										error!("ssl_add_chain_cert returned: {}", e);
									}
								}
							}
						} else {
							ext::ssl_use_certificate(ssl, &certs[0]).unwrap();
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
