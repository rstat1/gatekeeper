/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;
use pingora::{
	Error,
	ErrorType::{Custom, CustomCode, HTTPStatus, InternalError},
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tracing::debug;

use crate::data::DataStore;

pub struct RequestContext {
	base: String,
	service: String,
}

#[async_trait]
impl ProxyHttp for crate::gw::ReverseProxy {
	type CTX = RequestContext;
	fn new_ctx(&self) -> Self::CTX {
		RequestContext { base: String::new(), service: String::new() }
	}

	async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		let host = session.get_header("Host");
		let uri = session.req_header().uri.clone();

		if let Some(host) = host {
			let url: Uri = host.to_str().unwrap().parse().unwrap();
			let urlParts: Vec<&str> = host.to_str().unwrap().splitn(2, ".").collect();
			let mut base = urlParts[1].to_string();

			let port = url.port();
			if let Some(port) = port {
				base = base.replace(format!(":{}", port.as_str()).as_str(), "")
			}

			ctx.base = base.clone();
			ctx.service = urlParts[0].to_string();

			if self.epMgr.IsValidDomain(&base) {
				let (valid, aliasedService) = self.is_valid_service(&urlParts[0].to_string());
				if valid {
					if aliasedService != "" {
						ctx.service = aliasedService;
					}
					return Ok(false);
				}
			}
		}

		let h = ResponseHeader::build(404, None).unwrap();
		session.write_response_header(Box::new(h), true).await?;
		session
			.write_response_body(Some(Bytes::from(String::into_bytes(self.not_found_error(format!("{}.{}", ctx.service, ctx.base))))), true)
			.await?;
		session.set_keepalive(None);

		return Ok(true);
	}

	async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
		let serviceEP = self.epMgr.GetServiceEndpoint(&ctx.service);
		if let Some(serviceEP) = serviceEP {
			let peer = Box::new(HttpPeer::new(serviceEP, false, "".to_string()));
			Ok(peer)
		} else {
			let h = ResponseHeader::build(503, None).unwrap();
			session.write_response_header(Box::new(h), true).await?;
			session.write_response_body(Some(Bytes::from(String::into_bytes(self.no_endpoint_err()))), true).await?;
			session.set_keepalive(None);

			Err(Error::new_up(CustomCode("ServiceUnavilable", 503)))
		}
	}

	async fn response_filter(&self, _session: &mut Session, _upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()>
	where
		Self::CTX: Send + Sync,
	{
		Ok(())
	}
}
