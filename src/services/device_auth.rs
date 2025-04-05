/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::sync::Arc;

use async_trait::async_trait;

use base64::{
	alphabet,
	engine::{self, general_purpose},
	Engine,
};
use chrono::{Days, Utc};
use http::{Response, StatusCode, Uri};
use pingora::{apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use uuid::Uuid;

use crate::data::DataStore;

use super::cert_svc::CertManagerSvc;

pub struct DeviceAuthService {
	db: Arc<DataStore>,
	cm: Arc<CertManagerSvc>,
	gkCertExp: Option<u64>,
}
#[derive(Deserialize, Debug, Default, Serialize, Clone)]
struct DeviceAuthRequest {
	message: String,
	requestID: String,
}
#[derive(Deserialize, Debug, Default, Serialize, Clone)]
struct DeviceAuthRequestData {
	service: String,
	message: String,
}

#[derive(Deserialize, Debug, Default, Serialize, Clone)]
struct DeviceAuthClientResponse {
	message: String,
	signature: String,
	requestID: String,
}
#[derive(Serialize, Deserialize)]
struct DeviceAuthToken {
	pub payload: DeviceAuthTokenPayload,
	pub signature: String,
}
#[derive(Serialize, Deserialize)]
struct DeviceAuthTokenPayload {
	pub sub: String,
	pub exp: u64,
}

impl DeviceAuthService {
	pub fn Service(db: Arc<DataStore>, cm: Arc<CertManagerSvc>, gkCertExp: Option<u64>) -> Service<DeviceAuthService> {
		Service::new("Gatekeeper EDA".to_string(), DeviceAuthService { db, cm, gkCertExp })
	}
	fn GenerateRespInfo(&self) -> (String, String) {
		let requestID = Uuid::now_v7().to_string();
		const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";
		const MESSAGE_LEN: usize = 32;
		let mut rng = rand::rng();

		let message: String = (0..MESSAGE_LEN)
			.map(|_| {
				let idx = rng.random_range(0..CHARSET.len());
				CHARSET[idx] as char
			})
			.collect();

		(message, requestID)
	}
	async fn VerifyDeviceTokenRequest(&self, resp: DeviceAuthClientResponse) -> Result<bool, String> {
		debug!("verifying request ID: {}", resp.requestID);
		match self.db.ReadStringFromRedis(resp.requestID) {
			Ok(details) => {
				let req: DeviceAuthRequestData = serde_json::from_slice(details.as_bytes()).unwrap();
				match self.cm.VerifyMessage(req.service, req.message, resp.signature).await {
					Ok(r) => {
						debug!("verified!");
						Ok(r)
					}
					Err(e) => Err(format!("VerifyMessage failed: {e}")),
				}
			}
			Err(e) => Err(format!("ReadStringFromRedis failed: {e}")),
		}
	}
	async fn MakeDeviceToken(&self, serviceName: &String) -> Result<String, String> {
		let exp = self.gkCertExp.unwrap_or(Utc::now().checked_add_days(Days::new(30)).unwrap_or_default().timestamp().try_into().unwrap());
		match serde_json::to_string(&DeviceAuthTokenPayload { sub: serviceName.clone(), exp }) {
			Ok(token) => match self.cm.SignWithGatekeeperCert(token.clone()).await {
				Ok(sig) => Ok(format!("{}.{}", engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(token), sig).to_string()),
				Err(e) => Err(e),
			},
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn VerifyDeviceToken(&self, token: String) -> Result<bool, String> {
		let parts: Vec<&str> = token.split('.').collect();

		let msgDecoded = String::from_utf8(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).decode(parts[0].to_string()).unwrap()).unwrap();
		let sigDecoded = String::from_utf8(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).decode(parts[1].to_string()).unwrap()).unwrap();

		match self.cm.VerifyMessage("gatekeeper".to_string(), msgDecoded, sigDecoded).await {
			Ok(_) => todo!(),
			Err(_) => todo!(),
		}
	}
}

#[async_trait]
impl ServeHttp for DeviceAuthService {
	async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
		let uri: Uri;
		let mut path: String;
		let mimeType = "application/json";
		let mut sc: StatusCode = StatusCode::OK;
		let mut resp_body: Vec<u8> = Vec::default();

		if http_session.is_http2() {
			uri = http_session.as_http2().unwrap().req_header().uri.clone();
			path = uri.path().to_string();
		} else {
			uri = http_session.get_header("Host").unwrap().to_str().unwrap().parse().unwrap();
			path = http_session.req_header().uri.to_string();
		}

		let host = uri.authority().unwrap().to_string();
		let urlParts: Vec<&str> = host.splitn(2, ".").collect();
		let svc = &urlParts[0].to_string();

		if path.starts_with("/device_auth") {
			match path.split_off(12).as_str() {
				"/begin" => match self.db.GetServiceEDLSetting(svc).await {
					Ok(allowed) => {
						if allowed {
							let (message, requestID) = self.GenerateRespInfo();
							debug!("request ID {requestID} is allowed to do a device login");
							let resp = serde_json::to_string(&DeviceAuthRequest { message: message.clone(), requestID: requestID.clone() }).unwrap();
							let reqData = serde_json::to_string(&DeviceAuthRequestData { service: urlParts[0].to_string(), message: message.clone() }).unwrap();

							match self.db.WriteStringToRedisWithTTL(&requestID, &reqData, 120) {
								Ok(_) => resp_body = Vec::from(resp.as_bytes()),
								Err(e) => {
									sc = StatusCode::INTERNAL_SERVER_ERROR;
									error!("caching device auth info failed: {e}")
								}
							};
						} else {
							sc = StatusCode::FORBIDDEN;
						}
					}
					Err(e) => {
						sc = StatusCode::INTERNAL_SERVER_ERROR;
						error!("GetServiceEDLSetting error: {e}");
					}
				},
				"/finish" => match http_session.read_request_body().await {
					Ok(b) => {
						if let Some(authRequest) = b {
							match serde_json::from_slice::<DeviceAuthClientResponse>(&authRequest) {
								Ok(dacr) => match self.VerifyDeviceTokenRequest(dacr).await {
									Ok(r) => {
										if r {
											match self.MakeDeviceToken(svc).await {
												Ok(token) => {
													resp_body = Vec::from(token.as_bytes());
												}
												Err(e) => {
													sc = StatusCode::INTERNAL_SERVER_ERROR;
													resp_body = Vec::from("error generating token");
													error!("error generating token: {e}");
												}
											}
										} else {
											sc = StatusCode::BAD_REQUEST;
											resp_body = Vec::from("Validation failed. This should be an error".as_bytes());
										}
									}
									Err(e) => {
										sc = StatusCode::INTERNAL_SERVER_ERROR;
										resp_body = Vec::from("error verifying request");
										error!("error verifying request: {e}");
									}
								},
								Err(e) => {
									sc = StatusCode::INTERNAL_SERVER_ERROR;
									resp_body = Vec::from("error verifying request");
									error!("error verifying request: {e}");
								}
							}
						}
					}
					Err(e) => {
						sc = StatusCode::BAD_REQUEST;
						resp_body = Vec::from(format!("an error occured: {e}").as_bytes());
					}
				},
				"/renew" => {
					sc = StatusCode::NOT_IMPLEMENTED;
				}
				_ => {
					sc = StatusCode::NOT_FOUND;
				}
			}
		}

		Response::builder()
			.status(sc)
			.header(http::header::CONTENT_TYPE, mimeType)
			.header(http::header::CONTENT_LENGTH, resp_body.len())
			.body(resp_body)
			.unwrap()
	}
}
