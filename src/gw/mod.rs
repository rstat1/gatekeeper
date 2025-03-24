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
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tonic::async_trait;
use tracing::debug;

use crate::data::{Alias, DataStore, GatekeeperService};
use crate::services::endpoint_manager::EndpointManagerImpl;

pub mod gateway;
pub struct DynamicCert;
pub struct ReverseProxy {
	svcNames: Vec<String>,
	staticFileServerAddr: String,
	epMgr: Arc<EndpointManagerImpl>,
	aliasToSvc: HashMap<String, String>,
}


impl ReverseProxy {
	pub fn new(epMgr: Arc<EndpointManagerImpl>, svcs: Vec<GatekeeperService>, staticFileServerAddr: &String) -> Self {
		let mut svcNames: Vec<String> = Vec::default();
		let mut aliasToSvc: HashMap<String, String> = HashMap::default();

		for svc in svcs {
			svcNames.push(svc.name.clone());
			if let Some(aliases) = svc.routeAliases {
				for alias in aliases {
					aliasToSvc.insert(alias.alias, svc.name.clone());
				}
			}
		}

		ReverseProxy { epMgr, svcNames, aliasToSvc, staticFileServerAddr: staticFileServerAddr.clone() }
	}

	
	pub(super) fn is_valid_service(&self, svc: &String) -> (bool, String) {
		if self.svcNames.contains(svc) {
			(true, "".to_string())
		} else if self.aliasToSvc.contains_key(svc) {
			(true, self.aliasToSvc[svc].clone())
		} else {
			(false, "".to_string())
		}
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
				let cert = X509::from_pem(&cert_bytes).unwrap();

				let key_bytes = std::fs::read(certKey).unwrap();
				let key = PKey::private_key_from_pem(&key_bytes).unwrap();

				ext::ssl_use_certificate(ssl, &cert).unwrap();
				ext::ssl_use_private_key(ssl, &key).unwrap();
			}
		}
	}
}
