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
use http::{header::AUTHORIZATION, Response, StatusCode, Uri};
use pingora::{apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use uuid::Uuid;

use crate::{data::DataStore, pki::CertManagerSvc, services::v1::ServiceCredentials};

use super::endpoint_manager::EndpointManagerImpl;

pub struct ExternalDeviceManager {
	db: Arc<DataStore>,
	cm: Arc<CertManagerSvc>,
	gkCertExp: Option<u64>,
	epm: Arc<EndpointManagerImpl>,
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
	pub sub: String,
	pub exp: u64,
}

#[derive(Deserialize, Default)]
struct DeviceRegistrationData {
	deviceID: String,
	servicesAddr: String,
}

#[derive(Deserialize, Default)]
struct RenewalCheckRequest {
	serviceName: String,
	currentCertExpireTime: u64,
}

#[derive(Serialize, Default)]
struct RenewalCheckResponse {
	result: String,
	newCredentials: Option<String>,
}

impl ExternalDeviceManager {
	pub fn Service(db: Arc<DataStore>, cm: Arc<CertManagerSvc>, gkCertExp: Option<u64>, epm: Arc<EndpointManagerImpl>) -> Service<ExternalDeviceManager> {
		Service::new("Gatekeeper EDA".to_string(), ExternalDeviceManager { db, cm, gkCertExp, epm })
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

		if resp.message.is_empty() || resp.signature.is_empty() || resp.requestID.is_empty() {
			return Err("one or more invalid arguments in response".to_string());
		}

		match self.db.ReadStringFromRedis(resp.requestID) {
			Ok(details) => {
				let req: DeviceAuthRequestData = serde_json::from_slice(details.as_bytes()).unwrap_or_default();
				match self.cm.VerifySignature(req.service, &req.message, &resp.signature).await {
					Ok(r) => Ok(r),
					Err(e) => Err(format!("VerifyMessage failed: {e}")),
				}
			}
			Err(e) => Err(format!("ReadStringFromRedis failed: {e}")),
		}
	}
	async fn MakeDeviceToken(&self, serviceName: &String) -> Result<String, String> {
		let exp = self.gkCertExp.unwrap_or(Utc::now().checked_add_days(Days::new(30)).unwrap_or_default().timestamp().try_into().unwrap());
		match serde_json::to_string(&DeviceAuthToken { sub: serviceName.clone(), exp }) {
			Ok(token) => match self.cm.SignWithGatekeeperCert(token.clone()).await {
				Ok(sig) => Ok(format!("{}.{}", engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD).encode(token), sig).to_string()),
				Err(e) => Err(e),
			},
			Err(e) => Err(e.to_string()),
		}
	}
	pub async fn VerifyDeviceToken(&self, token: &str, svc: &String) -> Result<bool, String> {
		let parts: Vec<&str> = token.split('.').collect();
		let msgDecoded = String::from_utf8(engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD).decode(parts[0].to_string()).unwrap()).unwrap();
		match self.cm.VerifySignature("gatekeeper".to_string(), &msgDecoded, &parts[1].to_string()).await {
			Ok(r) => {
				if r {
					let currentTime: u64 = Utc::now().timestamp().try_into().unwrap();
					match serde_json::from_str::<DeviceAuthToken>(&msgDecoded.as_str()) {
						Ok(t) => {
							if currentTime > t.exp {
								return Err("token expired".to_string());
							} else {
								if t.sub != *svc {
									return Err("token invalid".to_string());
								}
								Ok(true)
							}
						}
						Err(e) => Err(e.to_string()),
					}
				} else {
					Ok(false)
				}
			}
			Err(e) => Err(e),
		}
	}
	async fn HandleDeviceAuth(&self, svc: &String, path: &String, http_session: &mut ServerSession) -> (StatusCode, Vec<u8>) {
		let mut sc: StatusCode = StatusCode::OK;
		let mut resp_body: Vec<u8> = Vec::default();
		let mut urlPath = path.clone();

		match urlPath.split_off(12).as_str() {
			"/begin" => match self.db.GetServiceEDLSetting(&svc).await {
				Ok(allowed) => {
					if allowed {
						let (message, requestID) = self.GenerateRespInfo();
						debug!("request ID {requestID} is allowed to do a device login");
						let resp = serde_json::to_string(&DeviceAuthRequest { message: message.clone(), requestID: requestID.clone() }).unwrap();
						let reqData = serde_json::to_string(&DeviceAuthRequestData { service: svc.clone(), message: message.clone() }).unwrap();

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
						let dacr = serde_json::from_slice::<DeviceAuthClientResponse>(&authRequest).unwrap_or_default();
						match self.VerifyDeviceTokenRequest(dacr).await {
							Ok(_) => match self.MakeDeviceToken(svc).await {
								Ok(token) => {
									resp_body = Vec::from(token.as_bytes());
								}
								Err(e) => {
									sc = StatusCode::INTERNAL_SERVER_ERROR;
									resp_body = Vec::from("error generating token");
									error!("error generating token: {e}");
								}
							},
							Err(e) => {
								sc = StatusCode::INTERNAL_SERVER_ERROR;
								resp_body = Vec::from(format!("error verifying request: {e}"));
								error!("error verifying request: {e}");
							}
						}
					}
				}
				Err(e) => {
					sc = StatusCode::BAD_REQUEST;
					resp_body = Vec::from(format!("an error occured reading request data: {e}").as_bytes());
				}
			},
			"/token_renew" => {
				sc = StatusCode::NOT_IMPLEMENTED;
			}
			_ => {
				sc = StatusCode::NOT_FOUND;
			}
		}
		(sc, resp_body)
	}
	async fn ActivateEPSForExtClient(&self, svc: &String, http_session: &mut ServerSession) -> (StatusCode, Vec<u8>) {
		let sc: StatusCode = StatusCode::OK;
		let resp_body: Vec<u8> = Vec::default();

		if http_session.req_header().headers.contains_key("Authorization") {
			let token = http_session.req_header().headers.get(AUTHORIZATION).unwrap().to_str().unwrap_or_default();
			match self.VerifyDeviceToken(token.strip_prefix("Bearer ").unwrap_or(token), svc).await {
				Ok(_) => {}
				Err(e) => {
					return self.ErrorResponse(e, "token verification failed", StatusCode::UNAUTHORIZED);
				}
			}
		} else {
			return self.ErrorResponse("", "no auth token", StatusCode::BAD_REQUEST);
		}

		match http_session.read_request_body().await {
			Ok(b) => {
				if let Some(regData) = b {
					let drd = serde_json::from_slice::<DeviceRegistrationData>(&regData).unwrap_or_default();
					match self.epm.AddClientDeviceToPingerList(svc, drd.deviceID, drd.servicesAddr) {
						Ok(_) => {}
						Err(e) => {
							return self.ErrorResponse(e, "error occured during device eps activation", StatusCode::INTERNAL_SERVER_ERROR);
						}
					}
				} else {
					return self.ErrorResponse("", "request contained no data", StatusCode::BAD_REQUEST);
				}
			}
			Err(e) => {
				return self.ErrorResponse(e, "an error occurred reading request data", StatusCode::BAD_REQUEST);
			}
		}

		(sc, resp_body)
	}
	fn ErrorResponse<T>(&self, e: T, errorDescription: &str, sc: StatusCode) -> (StatusCode, Vec<u8>)
	where
		T: ToString,
	{
		error!("{errorDescription}: {}", e.to_string());
		(sc, Vec::from(errorDescription))
	}
	async fn UpdateDeviceCredentials(&self, svc: &String, http_session: &mut ServerSession) -> (StatusCode, Vec<u8>) {
		let sc: StatusCode = StatusCode::OK;
		let mut resp_body: Vec<u8> = Vec::default();

		if http_session.req_header().headers.contains_key("Authorization") {
			let token = http_session.req_header().headers.get(AUTHORIZATION).unwrap().to_str().unwrap_or_default();
			match self.VerifyDeviceToken(token.strip_prefix("Bearer ").unwrap_or(token), svc).await {
				Ok(_) => {}
				Err(e) => {
					return self.ErrorResponse(e, "token verification failed", StatusCode::UNAUTHORIZED);
				}
			}
		} else {
			return self.ErrorResponse("", "no auth token", StatusCode::BAD_REQUEST);
		}

		match http_session.read_request_body().await {
			Ok(b) => if let Some(regData) = b {				
				let req = serde_json::from_slice::<RenewalCheckRequest>(&regData).unwrap_or_default();
				match self.cm.GetServiceCredsIfExpired(req.currentCertExpireTime, &req.serviceName).await {
					Some(c) => {
						let newCreds = serde_json::to_string::<ServiceCredentials>(&c).unwrap();
						let resp = RenewalCheckResponse{result: "success".to_string(), newCredentials: Some(newCreds)};
						resp_body = serde_json::to_vec_pretty::<RenewalCheckResponse>(&resp).unwrap();
					},
					None => {
						let resp = RenewalCheckResponse{result: "not expired".to_string(), newCredentials: None};
						resp_body = serde_json::to_vec_pretty::<RenewalCheckResponse>(&resp).unwrap();
					}
				}
			},
			Err(e) => {
				return self.ErrorResponse(e, "an error occurred reading request data", StatusCode::BAD_REQUEST);
			}
		}

		(sc, resp_body)
	}
}

#[async_trait]
impl ServeHttp for ExternalDeviceManager {
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
			uri = http_session.get_header("Host").unwrap().to_str().unwrap().parse().unwrap();
			path = http_session.req_header().uri.to_string();
		}

		let host = uri.authority().unwrap().to_string();
		let urlParts: Vec<&str> = host.splitn(2, ".").collect();
		let svc = &urlParts[0].to_string();

		if path.starts_with("/device") {
			let function = path.strip_prefix("/device").unwrap();
			if function.starts_with("/auth") {
				let resp = self.HandleDeviceAuth(svc, &path, http_session).await;
				sc = resp.0;
				resp_body = resp.1;
			}
			if function.starts_with("/activate_eps") {
				let resp = self.ActivateEPSForExtClient(svc, http_session).await;
				sc = resp.0;
				resp_body = resp.1;
			}
			if function.starts_with("/update_credentials") {
				let resp = self.UpdateDeviceCredentials(svc, http_session).await;
				sc = resp.0;
				resp_body = resp.1;
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
