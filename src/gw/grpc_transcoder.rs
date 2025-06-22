/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use http::StatusCode;
use pingora::modules::http::{HttpModule, HttpModuleBuilder, Module};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde::Serialize;
use serde_json::Deserializer;
use std::{any::Any, ops::Add};
use tracing::{debug, error};

#[derive(Default)]
pub struct GRPCTranscoder {
	service: String,
	currentMaxLen: usize,
	currentBuffer: BytesMut,
	method: String,
	outputMessageType: String,
	descriptorPool: DescriptorPool,
	intialized: bool,
}

impl GRPCTranscoder {
	pub fn init(&mut self, service: String, method: String) {
		self.method = method;
		self.service = service;
		self.intialized = true;
		debug!("init self.serviceName = {}", self.service);
		let proto = std::fs::read(format!("descriptors/{}.pb", self.service)).unwrap();
		self.descriptorPool = DescriptorPool::decode(Bytes::from(proto)).unwrap();
		self.currentBuffer = BytesMut::new();
	}
}

impl HttpModuleBuilder for GRPCTranscoder {
	fn init(&self) -> Module {
		Box::new(GRPCTranscoder::default())
	}

	fn order(&self) -> i16 {
		0
	}
}

#[async_trait]
impl HttpModule for GRPCTranscoder {
	fn as_any(&self) -> &dyn Any {
		self
	}

	fn as_any_mut(&mut self) -> &mut dyn Any {
		self
	}

	async fn request_body_filter(&mut self, body: &mut Option<Bytes>, _end_of_stream: bool) -> Result<()> {
		if self.intialized {
			debug!("self.serviceName = {}", self.service);
			let rb: String;
			let md = self
				.descriptorPool
				.get_service_by_name(&self.service)
				.unwrap()
				.methods()
				.find(|n| n.method_descriptor_proto().name.as_ref().unwrap() == self.method.as_str());

			if let Some(reqBody) = body {
				rb = String::from_utf8_lossy(reqBody).to_string();
			} else {
				rb = "{}".to_string();
			}
			if let Some(method) = md {
				debug!("{}", method.input().full_name());
				let mut deserializer = Deserializer::from_str(rb.as_str());
				let dm = DynamicMessage::deserialize(method.input(), &mut deserializer).unwrap();
				let mut buf = BytesMut::with_capacity(dm.encoded_len() + 1);
				buf.put_u8(0);
				buf.put_u32(dm.encoded_len().try_into().unwrap());
				let _ = dm.encode(&mut buf);
				*body = Some(Bytes::from(buf.freeze()));
				self.outputMessageType = method.output().full_name().to_string();
			}
		}

		Ok(())
	}

	fn response_body_filter(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) -> Result<()> {
		if !self.intialized {
			return Ok(());
		}
		if end_of_stream {
			debug!("end of stream time to get to work on a {} byte buffer", self.currentMaxLen);
			if self.currentMaxLen > 0 {
				let md = self
					.descriptorPool
					.get_service_by_name(&self.service)
					.unwrap()
					.methods()
					.find(|n| n.method_descriptor_proto().name.as_ref().unwrap() == self.method.as_str());
				if let Some(method) = md {
					match DynamicMessage::decode(method.output(), self.currentBuffer.as_ref()) {
						Ok(msg) => {
							let mut serializer = serde_json::Serializer::new(vec![]);
							msg.serialize(&mut serializer).unwrap();
							let serializedMessage = Bytes::from(serializer.into_inner());
							body.replace(serializedMessage);
						}
						Err(e) => {
							error!("{:?}", e);
						}
					}
				} else {
					error!("no method descriptor");
				}
			} else {
				error!("empty response");
			}
		} else {
			if let Some(resp) = body {
				debug!("not end of stream {}", resp.len());
				self.currentMaxLen = self.currentMaxLen.add(resp.len());
				self.currentBuffer.reserve(resp.len());
				self.currentBuffer.put_slice(&resp);

				*body = None;
			}
		}
		Ok(())
	}
	async fn response_header_filter(&mut self, resp: &mut ResponseHeader, _end_of_stream: bool) -> Result<()> {
		if self.intialized {
			debug!("response_header_filter {} {:?}", self.currentMaxLen, resp.get_reason_phrase());
			if let Some(grpcStatus) = resp.headers.get("Grpc-Status") {
				if grpcStatus.to_str().unwrap() != "0" {
					let _ = resp.set_status(StatusCode::INTERNAL_SERVER_ERROR);
				}
			}
			if let Some(respReason) = resp.get_reason_phrase() {
				if respReason == "OK" {
					let _ = resp.insert_header("content-type", "application/json");
				}
			}
		}
		Ok(())
	}
}
