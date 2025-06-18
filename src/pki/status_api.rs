/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use http::{Response, StatusCode, Uri};
use pingora::{apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::RemoveElem;

#[derive(Serialize, Debug)]
pub enum CertificateType {
	Endpoint,
	Namespace,
}
#[derive(Serialize, Debug)]
pub enum UpdateStatus {
	Success,
	Failed { failureType: FailureType, reason: String },
}
#[derive(Serialize, Debug)]
pub enum FailureType {
	Propagation,
	Generation,
	Unknown,
}

#[derive(Serialize, Debug)]
pub struct CertUpdateResult {
	pub timestamp: i64,
	pub status: UpdateStatus,
}

#[derive(Serialize, Debug)]
pub struct RegisteredCertificate {
	pub issuedFor: String,
	pub certType: CertificateType,
}

pub struct CertStatusAPI {
	registry: Arc<CertStatusRegistry>,
}

#[derive(Default, Debug)]
pub struct CertStatusRegistry {
	registeredCerts: RwLock<Vec<RegisteredCertificate>>,
	updateResults: RwLock<HashMap<String, CertUpdateResult>>,
}

impl CertStatusRegistry {
	pub fn new() -> Self {
		Self { updateResults: RwLock::new(HashMap::default()), registeredCerts: RwLock::new(Vec::default()) }
	}
	pub async fn Add(&self, cert: RegisteredCertificate) {
		let mut certs = self.registeredCerts.write().await;
		let exists = certs.iter().any(|s| s.issuedFor == *cert.issuedFor);
		if !exists {
			certs.push(cert);
		}
	}
	pub async fn SetStatus(&self, result: CertUpdateResult, certName: &String) {
		let mut updates = self.updateResults.write().await;
		if let Some(oldResult) = updates.get_mut(certName) {
			*oldResult = result
		} else {
			updates.insert(certName.to_string(), result);
		}
	}
	pub async fn Remove(&self, certName: &String) {
		let mut certs = self.registeredCerts.write().await;
		if certs.len() != 0 {
			certs.remove_elem(|e| e.issuedFor == *certName);
		}
	}
	pub async fn GetRegisteredCertsAsJSON(&self) -> Result<String, String> {
		let certs = self.registeredCerts.read().await;
		if certs.len() > 0 {
			let certsJSON = certs.serialize(serde_json::value::Serializer).map_err(|e| String::from(e.to_string()))?;
			return Ok(certsJSON.to_string());
		}
		Ok("{}".to_string())
	}

}

impl CertStatusAPI {
	pub fn Service(registry: Arc<CertStatusRegistry>) -> Service<CertStatusAPI> {
		Service::new("Certificate Status API".to_string(), CertStatusAPI { registry })
	}
}
#[async_trait]
impl ServeHttp for CertStatusAPI {
	async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
		let uri: Uri;
		let path: String;
		let mimeType = "application/json";
		let mut sc: StatusCode = StatusCode::OK;
		let mut resp_body: Vec<u8> = Vec::default();

		if http_session.is_http2() {
			uri = http_session.as_http2().unwrap().req_header().uri.clone();
			path = uri.path().to_string();
		} else {
			path = http_session.req_header().uri.to_string();
		}

		match path.as_str() {
			"/api/certs/list" => match self.registry.GetRegisteredCertsAsJSON().await {
				Ok(resp) => resp_body = Vec::from(resp.as_bytes()),
				Err(e) => {
					sc = StatusCode::INTERNAL_SERVER_ERROR;
					resp_body = Vec::from(e.as_bytes());
				}
			},
			"/api/certs/status" => {}
			_ => sc = StatusCode::NOT_FOUND,
		}

		Response::builder()
			.status(sc)
			.header(http::header::CONTENT_TYPE, mimeType)
			.header(http::header::CONTENT_LENGTH, resp_body.len())
			.body(resp_body)
			.unwrap()
	}
}
