/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use base64::{alphabet, engine, engine::general_purpose, Engine};
use bytes::Bytes;
use derive_builder::Builder;
use rustify::{clients::reqwest::Client as HTTPClient, errors::ClientError, Client, Endpoint, MiddleWare};
use rustify_derive::Endpoint;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_derive::Deserialize;

use serde_json::Value;
use std::{collections::HashMap, env, sync::Arc};
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::SYSTEM_CONFIG;

#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/{self.mount}/data/{self.path}", method = "POST", builder = "true")]
#[builder(setter(into, strip_option), default)]
struct KVWriteRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub path: String,
	pub data: Value,
}
#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/{self.mount}/data/{self.path}", method = "GET", builder = "true", response = "KVReadResponse")]
#[builder(setter(into, strip_option), default)]
struct KVReadRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub path: String,
}
#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/{self.mount}/metadata/{self.path}", method = "GET", builder = "true", response = "KVListResponse")]
#[builder(setter(into, strip_option), default)]
struct KVListAllRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub path: String,
	#[endpoint(query)]
	pub list: bool,
}
#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/{self.mount}/data/{self.path}", method = "PATCH", builder = "true", response = "KVReadResponse")]
#[builder(setter(into, strip_option), default)]
struct KVPatchRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub path: String,
	pub data: Value,
}
#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/{self.mount}/metadata/{self.path}", method = "DELETE", builder = "true")]
#[builder(setter(into, strip_option), default)]
struct KVDestroyRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub path: String,
}

#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/auth/token/lookup-self", method = "GET", builder = "true", response = "TokenData")]
#[builder(setter(into, strip_option), default)]
struct LookupTokenRequest {}

#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/auth/token/renew-self", method = "GET", builder = "true", response = "TokenRenewResponse")]
#[builder(setter(into, strip_option), default)]
struct RenewTokenRequest {
	#[endpoint(skip)]
	pub role: String,
}

#[derive(Builder, Endpoint, Default)]
#[endpoint(path = "/v1/database/creds/{self.role}", method = "GET", builder = "true", response = "CreateDBCredsResponse")]
#[builder(setter(into, strip_option), default)]
struct CreateDBCredsRequest {
	#[endpoint(skip)]
	pub role: String,
}

#[derive(Builder, Debug, Default, Endpoint)]
#[endpoint(path = "/v1/{self.mount}/issuer/default/issue/{self.role}", method = "POST", response = "Certificate", builder = "true")]
#[builder(setter(into, strip_option), default)]
pub struct GenerateCertRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[endpoint(skip)]
	pub role: String,
	pub alt_names: Option<String>,
	pub common_name: Option<String>,
	pub exclude_cn_from_sans: Option<bool>,
	pub format: Option<String>,
	pub ip_sans: Option<String>,
	pub other_sans: Option<Vec<String>>,
	pub private_key_format: Option<String>,
	pub ttl: Option<String>,
	pub uri_sans: Option<String>,
	pub remove_roots_from_chain: Option<bool>,
}
#[derive(Builder, Debug, Default, Endpoint, Serialize)]
#[endpoint(path = "/v1/{self.mount}/revoke-with-key", method = "POST", response = "RevokeCertResponse", builder = "true")]
#[builder(setter(into, strip_option), default)]
pub struct RevokeCertRequest {
	#[endpoint(skip)]
	pub mount: String,
	#[serde(rename = "certificate")]
	pub certificate: String,
	#[serde(rename = "private_key")]
	pub privateKey: String,
}

#[derive(Builder, Debug, Default, Endpoint)]
#[endpoint(path = "/v1/transit/encrypt/{self.key_name}", method = "POST", response = "EncryptedResponse", builder = "true")]
#[builder(setter(into, strip_option), default)]
pub struct TransitEncryptRequest {
	#[endpoint(skip)]
	pub key_name: String,
	pub plaintext: String,
}

#[derive(Builder, Debug, Default, Endpoint)]
#[endpoint(path = "/v1/transit/decrypt/{self.key_name}", method = "POST", response = "DecryptedResponse", builder = "true")]
#[builder(setter(into, strip_option), default)]
pub struct TransitDecryptRequest {
	#[endpoint(skip)]
	pub key_name: String,
	pub ciphertext: String,
}

#[derive(Deserialize, Debug, Default, Serialize, Clone)]
pub struct Certificate {
	pub ca_chain: Option<Vec<String>>,
	pub certificate: String,
	pub expiration: Option<u64>,
	pub issuing_ca: String,
	pub private_key: String,
	pub private_key_type: String,
	pub serial_number: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EABCreateResponse {
	pub data: EABData,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EABData {
	#[serde(rename = "created_on")]
	pub created_on: String,
	pub id: String,
	#[serde(rename = "key_type")]
	pub key_type: String,
	#[serde(rename = "acme_directory")]
	pub acme_directory: String,
	pub key: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRenewResponse {}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenData {
	pub accessor: String,
	#[serde(rename = "creation_time")]
	pub creation_time: i64,
	#[serde(rename = "creation_ttl")]
	pub creation_ttl: i64,
	#[serde(rename = "display_name")]
	pub display_name: String,
	#[serde(rename = "entity_id")]
	pub entity_id: String,
	#[serde(rename = "expire_time")]
	pub expire_time: Value,
	#[serde(rename = "explicit_max_ttl")]
	pub explicit_max_ttl: i64,
	pub id: String,
	pub meta: Value,
	#[serde(rename = "num_uses")]
	pub num_uses: i64,
	pub orphan: bool,
	pub path: String,
	pub policies: Vec<String>,
	pub ttl: u64,
	#[serde(rename = "type")]
	pub type_field: String,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDBCredsResponse {
	pub data: DBCredentials,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct DBCredentials {
	pub username: String,
	pub password: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KVReadResponse {
	pub data: Value,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KVListResponse {
	pub keys: Value,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedResponse {
	pub ciphertext: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedResponse {
	pub plaintext: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCertResponse {
	pub revocation_time: String,
}

struct AddTokenMiddleware {
	pub token: String,
}
struct TokenRenewer {
	client: Arc<VaultClient>,
}

#[derive(Deserialize, Debug)]
pub struct VaultResult<T> {
	pub data: Option<T>,
	pub auth: Option<AuthInfo>,
	pub lease_id: String,
	pub lease_duration: u32,
	pub renewable: bool,
	pub request_id: String,
	pub warnings: Option<Vec<String>>,
	pub wrap_info: Option<WrapInfo>,
}

/// The information stored in the optional `wrap_info` field of API responses
#[derive(Deserialize, Debug, Default)]
pub struct WrapInfo {
	pub token: String,
	pub accessor: String,
	pub ttl: u64,
	pub creation_time: String,
	pub creation_path: String,
}

/// The information stored in the optional `auth` field of API responses
#[derive(Deserialize, Debug)]
pub struct AuthInfo {
	pub client_token: String,
	pub accessor: String,
	pub policies: Vec<String>,
	pub token_policies: Vec<String>,
	pub metadata: Option<HashMap<String, String>>,
	pub lease_duration: u64,
	pub renewable: bool,
	pub entity_id: String,
	pub token_type: String,
	pub orphan: bool,
}
pub struct WrappedResponse<E: Endpoint> {
	pub info: WrapInfo,
	pub endpoint: rustify::endpoint::EndpointResult<E::Response>,
}
pub struct VaultClient {
	dev: bool,
	httpClient: Client,
	atm: AddTokenMiddleware,
}

impl<T: DeserializeOwned + Send + Sync> rustify::endpoint::Wrapper for VaultResult<T> {
	type Value = T;
}

impl MiddleWare for AddTokenMiddleware {
	fn request<E: Endpoint>(&self, _: &E, req: &mut http::Request<Vec<u8>>) -> Result<(), rustify::errors::ClientError> {
		if !self.token.is_empty() {
			req.headers_mut().append("X-Vault-Token", http::HeaderValue::from_str(self.token.as_str()).unwrap());
		}
		Ok(())
	}
	fn response<E: Endpoint>(&self, _: &E, _: &mut http::Response<Vec<u8>>) -> Result<(), ClientError> {
		Ok(())
	}
}

pub fn getActualResponse<T>(result: VaultResult<T>) -> Option<T>
where
	T: DeserializeOwned + Send + Sync,
{
	if let Some(w) = &result.warnings {
		if !w.is_empty() {
			warn!("Detected warnings in API response: {:#?}", w);
		}
	}
	result.data
}
impl VaultClient {
	pub async fn new(vault_ep: &String, dev: bool) -> Result<Arc<Self>, String> {
		match env::var_os("INITTOKEN") {
			Some(t) => {
				if let Ok(init_token) = t.into_string() {
					let mut httpClient = reqwest::ClientBuilder::new().use_rustls_tls();
					let certFile = std::fs::read_to_string("").unwrap_or("".to_string());
					httpClient = httpClient.add_root_certificate(reqwest::Certificate::from_pem(&Bytes::from(certFile)).unwrap());

					httpClient = httpClient.danger_accept_invalid_certs(true);
					let httpClient = httpClient.build().unwrap();
					let httpC = HTTPClient::new(vault_ep, httpClient);

					let vault = Arc::new(Self { httpClient: httpC, atm: AddTokenMiddleware { token: init_token }, dev });

					let tokenReq = LookupTokenRequest::builder().build().unwrap();
					let result = tokenReq.with_middleware(&vault.atm).exec(&vault.httpClient).await.unwrap().wrap::<VaultResult<_>>();
					match result {
						Ok(r) => {
							let resp: TokenData = getActualResponse(r).unwrap();
							if resp.ttl == 0 {
								warn!("token has no ttl?");
							} else {
								info!("renew token in {} seconds", resp.ttl - 45);
								vault.startRenewalTimer(resp.ttl - 45).await;
							}
							return Ok(vault);
						}
						Err(e) => {
							match &e {
								ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
								ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
								_ => error!("{}", &e),
							}
							Err(e.to_string())
						}
					}
				} else {
					Err("invalid init token".to_string())
				}
			}
			None => Err("no init token".to_string()),
		}
	}
	pub async fn GetDBCredentials(&self, dev: bool) -> Result<DBCredentials, String> {
		let mut role: String = "platform-service".to_string();
		if dev {
			role = "platform-dev".to_string();
		}
		let credsReq = CreateDBCredsRequest::builder().role(role).build().unwrap();
		let result = credsReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(r) => {
				let resp: CreateDBCredsResponse = r.parse().unwrap();
				return Ok(resp.data);
			}
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn ReadValueFromKV(&self, path: &str, mount: &str) -> Result<Value, String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let kvReq = KVReadRequest::builder().mount(mountPath).path(path.to_string()).build().unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(r) => {
				let res = r.wrap::<VaultResult<_>>().unwrap();
				let resp: KVReadResponse = getActualResponse(res).unwrap();
				let data: serde_json::Value = serde_json::from_value(resp.data).unwrap();

				return Ok(data.clone());
			}
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("ReadValueFromKV {}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("ReadValueFromKV {}: {:?}", source, content),
					_ => error!("ReadValueFromKV: {}", &e),
				}
				Err(format!("ReadValueFromKV: {}", e.to_string()))
			}
		}
	}
	pub async fn ListAllKeysAtKVPath(&self, mount: &str, path: Option<&str>) -> Result<Option<Value>, String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let mut builder = KVListAllRequest::builder();
		let mut kvReq = builder.mount(mountPath);
		if path.is_some() {
			kvReq = kvReq.path(path.unwrap());
		}

		let result = kvReq.list(true).build().unwrap().with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(r) => {
				let res = r.wrap::<VaultResult<_>>().unwrap();
				let resp: KVListResponse = getActualResponse(res).unwrap();
				let data: serde_json::Value = serde_json::from_value(resp.keys).unwrap();

				return Ok(Some(data.clone()));
			}
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => {
						if code == &404 {
							return Ok(None);
						} else {
							error!("ListAllKeysAtKVPath {}: {:?}", code, content);
							return Err(format!("ListAllKeysAtKVPath response error {}: {:?}", code, content));
						}
					}
					ClientError::ResponseParseError { source, content } => {
						error!("ListAllKeysAtKVPath {}: {:?}", source, content);
						return Err(format!("ListAllKeysAtKVPath parse error:  {}: {:?}", source, content));
					}
					_ => {
						error!("ListAllKeysAtKVPath general error: {}", &e);
						return Err(format!("ListAllKeysAtKVPath general error: {}", &e));
					}
				}
				// Err(format!("ListAllKeysAtKVPath: {}", e.to_string()))
			}
		}
	}
	pub async fn WriteValueToKV<T: Serialize>(&self, path: &str, key: &str, value: T, mount: &str) -> Result<(), String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let data: HashMap<&str, T> = HashMap::from([(key, value)]);
		let data_value_json = data.serialize(serde_json::value::Serializer).map_err(|e| String::from(e.to_string()))?;
		let kvReq = KVWriteRequest::builder().mount(mountPath).path(path.to_string()).data(data_value_json).build().unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}

	pub async fn WriteStructToKV<T: Serialize>(&self, path: &str, mount: &str, structToWrite: &T) -> Result<(), String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let data_value_json = structToWrite.serialize(serde_json::value::Serializer).map_err(|e| String::from(e.to_string()))?;
		let kvReq = KVWriteRequest::builder().mount(mountPath).path(path.to_string()).data(data_value_json).build().unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}

	pub async fn WriteJSONToKV(&self, path: &str, jsonToWrite: &str, mount: &str) -> Result<(), String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let kvReq = KVWriteRequest::builder()
			.mount(mountPath)
			.path(path.to_string())
			.data(format!("{{ \"data\": {{ {jsonToWrite} }} }}"))
			.build()
			.unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn PatchKVPair<T: Serialize>(&self, path: &str, key: &str, value: T, mount: &str) -> Result<(), String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}
		let data: HashMap<&str, T> = HashMap::from([(key, value)]);
		let data_value_json = data.serialize(serde_json::value::Serializer).map_err(|e| String::from(e.to_string()))?;
		let kvReq = KVPatchRequest::builder().mount(mountPath).path(path.to_string()).data(data_value_json).build().unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn DeleteKVPair(&self, path: &str, mount: &str) -> Result<(), String> {
		let mut mountPath: String = mount.to_string();
		if mount == "" {
			mountPath = "gatekeeper".to_string()
		}
		if self.dev {
			mountPath = format!("{}-dev", mount)
		}

		let kvReq = KVDestroyRequest::builder().mount(mountPath).path(path).build().unwrap();
		let result = kvReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn GenerateServiceCert(&self, role: &str, common_name: &str) -> Result<Certificate, String> {
		let mut certRole: String = role.to_string();
		if self.dev {
			certRole = format!("{}-dev", role)
		}
		
		let certReq = GenerateCertRequest::builder()
			.mount(&SYSTEM_CONFIG.vaultCAName)
			.role(certRole)
			.common_name(common_name.to_string())
			.build()
			.unwrap();
		let result = certReq.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<VaultResult<_>>();

		match result {
			Ok(r) => Ok(getActualResponse(r).unwrap()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn RevokeServiceCert(&self, certificate: String, key: String) -> Result<(), String> {
		let req = RevokeCertRequest::builder().mount(&SYSTEM_CONFIG.vaultCAName).certificate(certificate).privateKey(key).build().unwrap();
		let result = req.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<VaultResult<_>>();
		match result {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn Encrypt(&self, key_name: &str, plaintext: &str) -> Result<EncryptedResponse, String> {
		let plaintext_encoded = engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD).encode(plaintext);
		let req = TransitEncryptRequest::builder().key_name(key_name.to_string()).plaintext(plaintext_encoded).build().unwrap();
		let result = req.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<VaultResult<_>>();
		match result {
			Ok(r) => Ok(getActualResponse(r).unwrap()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	pub async fn Decrypt(&self, key_name: &str, cipherText: &str) -> Result<DecryptedResponse, String> {
		let req = TransitDecryptRequest::builder().key_name(key_name.to_string()).ciphertext(cipherText).build().unwrap();
		let result = req.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<VaultResult<_>>();

		match result {
			Ok(r) => Ok(getActualResponse(r).unwrap()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
	async fn startRenewalTimer(self: &Arc<Self>, ttl: u64) {
		let renewer = Arc::new(TokenRenewer { client: Arc::clone(&self) });
		renewer.StartRenewal(ttl);
	}
	async fn renewToken(&self) -> Result<(), String> {
		let renewReq = RenewTokenRequest::builder().build().unwrap();
		let resp = renewReq.with_middleware(&self.atm).exec(&self.httpClient).await;
		//TODO: retry?
		match resp {
			Ok(_) => Ok(()),
			Err(e) => {
				match &e {
					ClientError::ServerResponseError { code, content } => error!("{}: {:?}", code, content),
					ClientError::ResponseParseError { source, content } => error!("{}: {:?}", source, content),
					_ => error!("{}", &e),
				}
				Err(e.to_string())
			}
		}
	}
}

impl TokenRenewer {
	pub fn StartRenewal(self: &Arc<Self>, token_ttl: u64) {
		let self_clone = Arc::clone(self);
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(Duration::from_secs(token_ttl)).await;
				match self_clone.client.renewToken().await {
					Ok(_) => {}
					Err(e) => {
						warn!(e)
					}
				}
			}
		});
	}
}
