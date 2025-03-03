/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

use http::Uri;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use std::path::Path;
use std::sync::Arc;
use tonic::async_trait;
use tracing::debug;

use crate::data::DataStore;
use crate::services::service_registry::ServiceRegistryImpl;

pub mod gateway;
pub struct DynamicCert;
pub struct ReverseProxy {
    svcs: Arc<ServiceRegistryImpl>,
}

const ERROR_PAGE: &'static str = include_str!("error_page.html");

impl ReverseProxy {
    pub fn new(sr: Arc<ServiceRegistryImpl>) -> Self {
        ReverseProxy { svcs: sr }
    }
    pub(super) fn generate_err_page(&self, code: String, error: String, err_details: String, reason: String) -> String {
        let mut page = ERROR_PAGE.to_string();

        page = page.replace("##ERROR##", &error);
        page = page.replace("##ERROR_CODE##", &code);
        page = page.replace("##ERROR_REASON##", &reason);
        page = page.replace("##ERROR_DESCRIPTION##", &err_details);

        return page;
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
