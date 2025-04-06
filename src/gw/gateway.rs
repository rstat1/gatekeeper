/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Uri};
use pingora::{
	modules::http::{
		grpc_web::{GrpcWeb, GrpcWebBridge},
		HttpModules,
	},
	protocols::ALPN,
	tls::{pkey::PKey, ssl::NameType, x509::X509},
	upstreams::peer::{Peer, PeerOptions},
	utils::tls::CertKey,
	Error,
	ErrorType::{self, Custom, CustomCode, HTTPStatus, InternalError},
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tracing::{debug, error, warn};
use tracing_subscriber::field::debug;

use crate::{data::DataStore, no_endpoint_err, not_found_error};

pub struct RequestContext {
	base: String,
	service: String,
	grpcService: String,
	isGRPCService: bool,
	redirectDeviceAuthAttempt: bool,
	redirectToStaticServer: bool,
	currentPeer: Option<SocketAddr>,
}

#[async_trait]
impl ProxyHttp for crate::gw::ReverseProxy {
	type CTX = RequestContext;
	fn new_ctx(&self) -> Self::CTX {
		RequestContext {
			base: String::new(),
			service: String::new(),
			currentPeer: None,
			redirectToStaticServer: false,
			isGRPCService: false,
			grpcService: String::new(),
			redirectDeviceAuthAttempt: false,
		}
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
		let contentTypeHeader = session.get_header("content-type");

		if session.is_http2() {
			uri = session.as_http2().unwrap().req_header().uri.clone();
		} else {
			uri = session.get_header("Host").unwrap().to_str().unwrap().parse().unwrap();
		}

		if let Some(isGRPC) = contentTypeHeader {
			ctx.isGRPCService = isGRPC.to_str().unwrap() == "application/grpc";
		}

		if let Some(isDevAuthSvc) = contentTypeHeader {
			ctx.redirectDeviceAuthAttempt = isDevAuthSvc.to_str().unwrap() == "application/x-gatekeeper-device-api";
			if ctx.redirectDeviceAuthAttempt {
				return Ok(false);
			}
		}

		if !uri.path().starts_with("/api") && !ctx.isGRPCService && !ctx.redirectDeviceAuthAttempt {
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

		if ctx.isGRPCService {
			ctx.grpcService = uri.path().split("/").collect::<Vec<&str>>()[1].to_string();
		}

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
		let mut svcNameForLookup: String;

		if ctx.redirectToStaticServer {
			debug!("forward to StaticFile service");
			let peer = Box::new(HttpPeer::new(self.staticFileServerAddr.clone(), false, "".to_string()));
			return Ok(peer);
		}

		if ctx.redirectDeviceAuthAttempt {
			debug!("forward to EDA service");
			let peer = Box::new(HttpPeer::new(self.deviceAuthServerAddr.clone(), false, "".to_string()));
			return Ok(peer);
		}

		debug!("serving request to service: {}", &ctx.service);

		if ctx.isGRPCService {
			svcNameForLookup = ctx.grpcService.clone();
		} else {
			svcNameForLookup = ctx.service.clone();
		}

		let serviceEP = self.epMgr.GetServiceEndpoint(&svcNameForLookup);
		if let Some(serviceEP) = serviceEP {
			debug!("serving gRPC request {:?}", serviceEP);
			ctx.currentPeer = Some(serviceEP);
			if ctx.isGRPCService {
				let caChain = self.grpcCert.ca_chain.as_ref().unwrap();

				let cert = X509::from_pem(&Bytes::from(self.grpcCert.certificate.clone())).unwrap();
				let caInt = X509::from_pem(&Bytes::from(caChain[0].clone())).unwrap();
				let caRoot = X509::from_pem(&Bytes::from(caChain[1].clone())).unwrap();

				let key = PKey::private_key_from_pem(&Bytes::from(self.grpcCert.private_key.clone())).unwrap();
				let mut peer = HttpPeer::new(serviceEP, true, ctx.service.clone());
				let mut peerOpts = PeerOptions::new();

				peer.client_cert_key = Some(Arc::new(CertKey::new(vec![cert], key)));
				peerOpts.alpn = ALPN::H2;
				peerOpts.ca = Some(Arc::new(Box::new([caInt.clone(), caRoot.clone()])));
				peer.options = peerOpts;

				let peerBox = Box::new(peer);
				Ok(peerBox)
			} else {
				let peer = Box::new(HttpPeer::new(serviceEP, false, "".to_string()));
				Ok(peer)
			}
		} else {
			let h = ResponseHeader::build(503, None).unwrap();
			session.write_response_header(Box::new(h), true).await?;
			session.write_response_body(Some(Bytes::from(String::into_bytes(no_endpoint_err()))), true).await?;
			session.set_keepalive(None);

			Err(Error::new_up(CustomCode("ServiceUnavilable", 503)))
		}
	}

	fn error_while_proxy(&self, peer: &HttpPeer, session: &mut Session, e: Box<Error>, _ctx: &mut Self::CTX, client_reused: bool) -> Box<Error> {
		let mut e = e.more_context(format!("Peer: {}", peer));
		// only reused client connections where retry buffer is not truncated
		e.retry.decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());

		error!("proxy err: {}", e);

		e
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
			return 503;
		} else if ctx.redirectToStaticServer {
			let h = ResponseHeader::build(404, None).unwrap();
			session.write_response_header(Box::new(h), true).await.unwrap();
			session
				.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(uri.path().to_string())))), true)
				.await
				.unwrap();
			session.set_keepalive(None);

			return 404;
		}
		error!("error: {}, ctx: {:?}", e, e.context);
		502
	}

	async fn response_filter(&self, _session: &mut Session, _upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()>
	where
		Self::CTX: Send + Sync,
	{
		Ok(())
	}
}
