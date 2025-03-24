/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Uri};
use pingora::{
	modules::http::{
		grpc_web::{GrpcWeb, GrpcWebBridge},
		HttpModules,
	},
	Error,
	ErrorType::{self, Custom, CustomCode, HTTPStatus, InternalError},
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, warn};

use crate::{data::DataStore, no_endpoint_err, not_found_error};

pub struct RequestContext {
	base: String,
	service: String,
	redirectToStaticServer: bool,
	currentPeer: Option<SocketAddr>,
}

#[async_trait]
impl ProxyHttp for crate::gw::ReverseProxy {
	type CTX = RequestContext;
	fn new_ctx(&self) -> Self::CTX {
		RequestContext { base: String::new(), service: String::new(), currentPeer: None, redirectToStaticServer: false }
	}

	fn init_downstream_modules(&self, modules: &mut HttpModules) {
		// Add the gRPC web module
		modules.add_module(Box::new(GrpcWeb))
	}

	async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
		if let Some(isGRPCWeb) = session.get_header("content-type") {
			if isGRPCWeb.to_str().unwrap().to_string().starts_with("application/grpc-web") {
				let grpc = session.downstream_modules_ctx.get_mut::<GrpcWebBridge>().expect("grpc-web module added");
				grpc.init();
			}
		}

		Ok(())
	}

	async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		let mut uri: Uri;

		if session.is_http2() {
			uri = session.as_http2().unwrap().req_header().uri.clone();
		} else {
			uri = session.get_header("Host").unwrap().to_str().unwrap().parse().unwrap();
		}

		if !(uri.path().starts_with("/api") || uri.path().starts_with("/rpc")) {
			ctx.redirectToStaticServer = true;
			return Ok(false);
		}

		let host = uri.authority().unwrap().to_string();
		let urlParts: Vec<&str> = host.splitn(2, ".").collect();
		let mut base = urlParts[1].to_string();

		let port = uri.port();
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

		let h = ResponseHeader::build(404, None).unwrap();
		session.write_response_header(Box::new(h), true).await?;
		session
			.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(format!("{}.{}", ctx.service, ctx.base))))), true)
			.await?;
		session.set_keepalive(None);

		return Ok(true);
	}

	async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
		if ctx.redirectToStaticServer {
			let peer = Box::new(HttpPeer::new(self.staticFileServerAddr.clone(), false, "".to_string()));
			return Ok(peer);
		}

		let serviceEP = self.epMgr.GetServiceEndpoint(&ctx.service);
		if let Some(serviceEP) = serviceEP {
			ctx.currentPeer = Some(serviceEP);
			let peer = Box::new(HttpPeer::new(serviceEP, false, "".to_string()));
			Ok(peer)
		} else {
			let h = ResponseHeader::build(503, None).unwrap();
			session.write_response_header(Box::new(h), true).await?;
			session.write_response_body(Some(Bytes::from(String::into_bytes(no_endpoint_err()))), true).await?;
			session.set_keepalive(None);

			Err(Error::new_up(CustomCode("ServiceUnavilable", 503)))
		}
	}

	fn fail_to_connect(&self, _session: &mut Session, peer: &HttpPeer, _ctx: &mut Self::CTX, e: Box<Error>) -> Box<Error> {
		if e.etype == ErrorType::ConnectRefused {
			return Box::new(Error { etype: e.etype, esource: e.esource, retry: pingora::RetryType::Decided(false), cause: e.cause, context: None });
		}
		Box::new(Error { etype: e.etype, esource: e.esource, retry: pingora::RetryType::Decided(true), cause: e.cause, context: None })
	}

	async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Self::CTX) -> u16
	where
		Self::CTX: Send + Sync,
	{
		let mut uri: Uri;

		if session.is_http2() {
			uri = session.as_http2().unwrap().req_header().uri.clone();
		} else {
			uri = session.req_header().uri.clone();
		}

		if e.etype == ErrorType::ConnectRefused && !ctx.redirectToStaticServer {
			warn!("failed to proxy request, {:?}", e);
			let h = ResponseHeader::build(503, None).unwrap();
			session.write_response_header(Box::new(h), true).await.unwrap();
			session.write_response_body(Some(Bytes::from(String::into_bytes(no_endpoint_err()))), true).await.unwrap();
			session.set_keepalive(None);
			503
		} else {
			let h = ResponseHeader::build(404, None).unwrap();
			session.write_response_header(Box::new(h), true).await.unwrap();
			session
				.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(uri.path().to_string())))), true)
				.await
				.unwrap();
			session.set_keepalive(None);

			404
		}
	}

	async fn response_filter(&self, _session: &mut Session, _upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()>
	where
		Self::CTX: Send + Sync,
	{
		Ok(())
	}
}
