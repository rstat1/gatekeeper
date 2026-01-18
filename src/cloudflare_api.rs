/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use chrono::{offset::Utc, DateTime};
use derive_builder::Builder;
use rustify::{clients::reqwest::Client as HTTPClient, errors::ClientError, Client, Endpoint, MiddleWare};
use rustify_derive::Endpoint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
	net::{Ipv4Addr, Ipv6Addr},
	sync::Arc,
};
use tracing::{debug, error, info};

pub struct CloudflareAPIClient {
	zoneID: String,
	httpClient: Client,
	atm: AddTokenMiddleware,
}
struct AddTokenMiddleware {
	pub token: String,
}

#[derive(Deserialize, Debug)]
pub struct ResponseMessage {
	pub code: i32,
	pub message: String,
	pub documentation_url: String,
}
#[derive(Deserialize)]
pub struct Response<ResultType> {
	pub success: bool,
	pub result: ResultType,
	pub errors: Vec<ResponseMessage>,
	pub messages: Vec<ResponseMessage>,
}

#[derive(Builder, Endpoint, Default, Serialize)]
#[endpoint(path = "/client/v4/zones/{self.zoneID}/dns_records", method = "POST", builder = "true", response = "Response<DNSRecordResponse>")]
#[builder(setter(into, strip_option), default)]
struct NewDNSRecord {
	#[endpoint(skip)]
	pub zoneID: String,
	pub name: String,
	pub ttl: i32,
	#[serde(flatten)]
	pub content: DNSRecordContent,
}

#[derive(Builder, Endpoint, Default, Serialize)]
#[endpoint(
	path = "/client/v4/zones/{self.zoneID}/dns_records/{self.dnsRecordID}",
	method = "PATCH",
	builder = "true",
	response = "Response<DNSRecordResponse>"
)]
#[builder(setter(into, strip_option), default)]
struct UpdateDNSRecord {
	#[endpoint(skip)]
	pub zoneID: String,
	#[endpoint(skip)]
	pub dnsRecordID: String,
	pub ttl: i32,
	#[serde(flatten)]
	pub content: DNSRecordContent,
}

#[derive(Builder, Endpoint, Default, Serialize)]
#[endpoint(
	path = "/client/v4/zones/{self.zoneID}/dns_records/{self.dnsRecordID}",
	method = "DELETE",
	builder = "true",
	response = "Response<DeleteDNSRecordResponse>"
)]
#[builder(setter(into, strip_option), default)]
struct DeleteDNSRecord {
	#[endpoint(skip)]
	pub zoneID: String,
	#[endpoint(skip)]
	pub dnsRecordID: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum DNSRecordContent {
	A { content: Ipv4Addr },
	AAAA { content: Ipv6Addr },
	CNAME { content: String },
	NS { content: String },
	MX { content: String, priority: u16 },
	TXT { content: String, comment: String },
	SRV { content: String },
}

#[derive(Deserialize, Debug)]
pub struct Meta {}

#[derive(Deserialize, Debug)]
pub struct DNSRecordResponse {
	/// Extra Cloudflare-specific information about the record
	pub meta: Meta,
	/// DNS record name
	pub name: String,
	/// Time to live for DNS record. Value of 1 is 'automatic'
	pub ttl: u32,
	/// When the record was last modified
	pub modified_on: DateTime<Utc>,
	/// When the record was created
	pub created_on: DateTime<Utc>,
	/// Whether this record can be modified/deleted (true means it's managed by Cloudflare)
	pub proxiable: bool,
	/// Type of the DNS record that also holds the record value
	#[serde(flatten)]
	pub content: DNSRecordContent,
	/// DNS record identifier tag
	pub id: String,
	/// Whether the record is receiving the performance and security benefits of Cloudflare
	pub proxied: bool,
}

#[derive(Deserialize, Debug)]
pub struct DeleteDNSRecordResponse {
	pub id: String,
}

impl<T: DeserializeOwned + Send + Sync> rustify::endpoint::Wrapper for Response<T> {
	type Value = Response<T>;
}

impl Default for DNSRecordContent {
	fn default() -> Self {
		DNSRecordContent::A { content: Ipv4Addr::new(0, 0, 0, 0) }
	}
}

impl MiddleWare for AddTokenMiddleware {
	fn request<E: Endpoint>(&self, _: &E, req: &mut http::Request<Vec<u8>>) -> Result<(), rustify::errors::ClientError> {
		if !self.token.is_empty() {
			req.headers_mut()
				.append(http::header::AUTHORIZATION, http::HeaderValue::from_str(format!("Bearer {}", self.token).as_str()).unwrap());
		}
		Ok(())
	}
	fn response<E: Endpoint>(&self, _: &E, _: &mut http::Response<Vec<u8>>) -> Result<(), ClientError> {
		Ok(())
	}
}

impl CloudflareAPIClient {
	pub fn new(token: String, zoneID: String) -> Arc<Self> {
		let httpClient = HTTPClient::new("https://api.cloudflare.com", reqwest::ClientBuilder::new().use_rustls_tls().build().unwrap());
		Arc::new(CloudflareAPIClient { atm: AddTokenMiddleware { token }, zoneID, httpClient })
	}

	pub async fn CreateNewTXTRecord(&self, recordName: &String, content: String, comment: &str) -> Result<String, String> {
		let newDNSReq = NewDNSRecord::builder()
			.zoneID(self.zoneID.clone())
			.name(recordName)
			.content(DNSRecordContent::TXT { content, comment: comment.to_string() })
			.ttl(60)
			.build()
			.unwrap();
		match newDNSReq.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<Response<DNSRecordResponse>>() {
			Ok(r) => {
				if r.errors.len() > 0 {
					return Err(format!("CreateNewTXTRecord {:?}", r.errors));
				}
				debug!("new txt record created: result = {:?}", r.result);
				Ok(r.result.id)
			}
			Err(err) => Err(format!("CreateNewTXTRecord: {}", err.to_string())),
		}
	}
	pub async fn UpdateTXTRecord(&self, recordID: &String, content: String, comment: &str) -> Result<String, String> {
		let newDNSReq = UpdateDNSRecord::builder()
			.zoneID(self.zoneID.clone())
			.dnsRecordID(recordID)
			.content(DNSRecordContent::TXT { content, comment: comment.to_string() })
			.ttl(60)
			.build()
			.unwrap();
		match newDNSReq.with_middleware(&self.atm).exec(&self.httpClient).await.unwrap().wrap::<Response<DNSRecordResponse>>() {
			Ok(r) => {
				if r.errors.len() > 0 {
					return Err(format!("UpdateTXTRecord {:?}", r.errors));
				}
				debug!("updated txt record created: result = {:?}", r.result);
				Ok(r.result.id)
			}
			Err(err) => Err(format!("UpdateTXTRecord: {}", err.to_string())),
		}
	}
	pub async fn DeleteDNSRecord(&self, recordID: &String) -> Result<(), String> {
		let deleteDNSReq = DeleteDNSRecord::builder().zoneID(self.zoneID.clone()).dnsRecordID(recordID).build().unwrap();
		match deleteDNSReq
			.with_middleware(&self.atm)
			.exec(&self.httpClient)
			.await
			.unwrap()
			.wrap::<Response<DeleteDNSRecordResponse>>()
		{
			Ok(_) => {
				info!("Deleted dns record successfully!");
				Ok(())
			}
			Err(e) => {
				error!("DeleteDNSRecord: {}", e.to_string());
				Err(format!("DeleteDNSRecord: {}", e.to_string()))
			}
		}
	}
}
