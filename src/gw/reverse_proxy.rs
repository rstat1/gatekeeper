/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use http::{
	header::{self},
	Method, Uri,
};
use pingora::{
	modules::http::{
		grpc_web::{GrpcWeb, GrpcWebBridge},
		HttpModules,
	},
	protocols::ALPN,
	tls::{pkey::PKey, x509::X509},
	upstreams::peer::PeerOptions,
	utils::tls::CertKey,
	Error,
	ErrorType::{self, CustomCode, ReadError},
	OrErr,
};
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use tracing::{debug, error, warn};

use crate::{no_endpoint_err, not_found_error};

use super::{grpc_transcoder::GRPCTranscoder, DEVICE_API_CONTENT_TYPE};

pub struct RequestContext {
	base: String,
	service: String,
	grpcService: String,
	isGRPCService: bool,
	redirectToStaticServer: bool,
	redirectDeviceAuthAttempt: bool,
	redirectToCertStatusServer: bool,
	currentPeer: Option<SocketAddr>,
	isHTTPToRPCRequest: bool,
	grpcMethodToCall: Option<String>,
	authority: String,
}

#[async_trait]
impl ProxyHttp for crate::gw::ReverseProxy {
	type CTX = RequestContext;
	fn new_ctx(&self) -> Self::CTX {
		RequestContext {
			currentPeer: None,
			base: String::new(),
			isGRPCService: false,
			service: String::new(),
			grpcMethodToCall: None,
			authority: String::new(),
			isHTTPToRPCRequest: false,
			grpcService: String::new(),
			redirectToStaticServer: false,
			redirectDeviceAuthAttempt: false,
			redirectToCertStatusServer: false,
		}
	}

	fn init_downstream_modules(&self, modules: &mut HttpModules) {
		modules.add_module(Box::new(GrpcWeb));
		modules.add_module(Box::new(GRPCTranscoder::default()));
	}

	async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
		let uri: Uri;

		if session.is_http2() {
			uri = session.as_http2().unwrap().req_header().uri.clone();
		} else {
			let host = session.get_header("Host").unwrap().to_str().unwrap().to_string();
			let path = session.req_header().uri.clone().to_string();
			let uriStr = format!("{}{}{}", "https://", host, path);
			uri = uriStr.parse().unwrap();
		}
		let urlParts: Vec<&str> = uri.path().split("/").collect::<Vec<&str>>();

		if let Some(isGRPCWeb) = session.get_header("content-type") {
			if isGRPCWeb.to_str().unwrap().to_string().starts_with("application/grpc-web") {
				let grpcWeb = session.downstream_modules_ctx.get_mut::<GrpcWebBridge>().expect("grpc-web module added");
				grpcWeb.init();
			}
		}

		let host = uri.authority().unwrap().to_string();
		let hostParts: Vec<&str> = host.splitn(2, ".").collect();
		let base = hostParts[1].to_string();

		if self.epMgr.IsValidDomain(&base).await {
			if self.epMgr.IsRPCGatewayEnabled(&hostParts[0].to_string()) && uri.path().starts_with("/rpc") {
				let grpcTranscode = session.downstream_modules_ctx.get_mut::<GRPCTranscoder>().expect("grpc-transcode module added");
				grpcTranscode.init(urlParts[2].to_string(), urlParts[3].to_string());
			}
		}

		Ok(())
	}

	async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
	where
		Self::CTX: Send + Sync,
	{
		let uri: Uri;
		let contentTypeHeader = session.get_header("content-type");

		if session.is_http2() {
			uri = session.as_http2().unwrap().req_header().uri.clone();
			ctx.authority = uri.authority().unwrap().as_str().to_string();
		} else {
			let host = session.get_header("Host").unwrap().to_str().unwrap().to_string();
			let path = session.req_header().uri.clone().to_string();
			let uriStr = format!("{}{}{}", "https://", host, path);
			uri = uriStr.parse().unwrap();
			ctx.authority = uri.authority().unwrap().as_str().to_string();
		}

		if let Some(isGRPC) = contentTypeHeader {
			ctx.isGRPCService = isGRPC.to_str().unwrap() == "application/grpc";
		}

		if let Some(isDevAuthSvc) = contentTypeHeader {
			ctx.redirectDeviceAuthAttempt = isDevAuthSvc.to_str().unwrap() == DEVICE_API_CONTENT_TYPE;
			if ctx.redirectDeviceAuthAttempt {
				return Ok(false);
			}
		}

		if !uri.path().starts_with("/api") && !uri.path().starts_with("/rpc") && !ctx.isGRPCService && !ctx.redirectDeviceAuthAttempt {
			ctx.redirectToStaticServer = true;
			return Ok(false);
		}

		let pathParts = uri.path().split("/").collect::<Vec<&str>>();
		let host = uri.authority().unwrap().to_string();
		let hostParts: Vec<&str> = host.splitn(2, ".").collect();
		let mut base = hostParts[1].to_string();

		let port = uri.port();
		if let Some(port) = port {
			base = base.replace(format!(":{}", port.as_str()).as_str(), "")
		}

		ctx.base = base.clone();
		ctx.service = hostParts[0].to_string();

		if ctx.service == "gatekeeper".to_string() {
			ctx.redirectToCertStatusServer = true;
			return Ok(false);
		}

		if ctx.isGRPCService {
			ctx.grpcService = uri.path().split("/").collect::<Vec<&str>>()[1].to_string();
		}

		if uri.path().starts_with("/rpc") {
			if self.epMgr.IsRPCGatewayEnabled(&hostParts[0].to_string()) {
				session
					.req_header_mut()
					.set_uri(format!("https://{}{}", ctx.authority, uri.path().strip_prefix("/rpc").unwrap()).parse().unwrap());
				let _ = session.req_header_mut().insert_header("content-type", "application/grpc");
				let _ = session.req_header_mut().insert_header("te", "trailers");
				session.req_header_mut().remove_header("accept");
				session.req_header_mut().set_method(Method::POST);
				session.req_header_mut().set_send_end_stream(false);

				ctx.isGRPCService = true;
				ctx.isHTTPToRPCRequest = true;
				ctx.grpcService = pathParts[2].to_string();
				ctx.grpcMethodToCall = Some(pathParts[3].to_string());
				debug!("grpcMethodToCall: {:?}", ctx.grpcMethodToCall);
			} else {
				let mut h = ResponseHeader::build(400, None).unwrap();
				let _ = h.insert_header("content-type", "text/html");
				session.write_response_header(Box::new(h), true).await?;
				session
					.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(format!("{}.{}", ctx.service, ctx.base))))), true)
					.await?;
				session.set_keepalive(None);

				return Ok(true);
			}
		}

		if self.epMgr.IsValidDomain(&base).await {
			let (valid, aliasedService) = self.epMgr.IsValidService(&hostParts[0].to_string());
			if valid {
				if aliasedService != "" {
					ctx.service = aliasedService;
				}
				return Ok(false);
			}
		}

		let mut h = ResponseHeader::build(404, None).unwrap();
		let _ = h.insert_header("content-type", "text/html");
		session.write_response_header(Box::new(h), true).await?;
		session
			.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(format!("{}.{}", ctx.service, ctx.base))))), true)
			.await?;
		session.set_keepalive(None);

		return Ok(true);
	}

	async fn response_trailer_filter(&self, _session: &mut Session, upstream_trailers: &mut header::HeaderMap, ctx: &mut Self::CTX) -> Result<Option<Bytes>>
	where
		Self::CTX: Send + Sync,
	{
		if ctx.isHTTPToRPCRequest {
			debug!("write trailer(s)");
			// TODO compressed trailer?
			// grpc-web trailers frame head
			const GRPC_WEB_TRAILER: u8 = 0x80;

			// number of bytes in trailer header
			const GRPC_TRAILER_HEADER_LEN: usize = 5;

			// just some estimate
			const DEFAULT_TRAILER_BUFFER_SIZE: usize = 256;

			let mut buf = BytesMut::with_capacity(DEFAULT_TRAILER_BUFFER_SIZE);
			let mut trailers = buf.split_off(GRPC_TRAILER_HEADER_LEN);

			// iterate the key/value pairs and encode them into the tmp buffer
			for (key, value) in upstream_trailers.iter() {
				// encode header
				trailers.put_slice(key.as_ref());
				trailers.put_slice(b":");

				// encode value
				trailers.put_slice(value.as_ref());

				// encode header separator
				trailers.put_slice(b"\r\n");
			}

			// ensure trailer length within u32
			let len = trailers.len().try_into().or_err_with(ReadError, || format!("invalid gRPC trailer length: {}", trailers.len()))?;
			buf.put_u8(GRPC_WEB_TRAILER);
			buf.put_u32(len);
			buf.unsplit(trailers);
			return Ok(Some(buf.freeze()));
		}
		Ok(None)
	}

	async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
		let svcNameForLookup: String;

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

		if ctx.redirectToCertStatusServer {
			debug!("forward to CertStatus service");
			let peer = Box::new(HttpPeer::new(self.certStatusServerAddr.clone(), false, "".to_string()));
			return Ok(peer);
		}

		if ctx.isGRPCService {
			svcNameForLookup = ctx.grpcService.clone();
		} else {
			svcNameForLookup = ctx.service.clone();
		}

		debug!("serving request to service: {}", svcNameForLookup);

		let serviceEP = self.epMgr.GetServiceEndpoint(&svcNameForLookup);
		if let Some(serviceEP) = serviceEP {
			debug!("serving gRPC request {:?}", serviceEP);
			ctx.currentPeer = Some(serviceEP);
			if ctx.isGRPCService {
				let grpcCert = self.cmSvc.GetExistingServiceCert("gatekeeper".to_string()).await.unwrap();
				let caChain: Vec<String> = grpcCert.ca_cert.clone().split_inclusive("-----END CERTIFICATE-----").map(|s| s.to_string()).collect();

				let cert = X509::from_pem(&Bytes::from(grpcCert.certificate.clone())).unwrap();
				let caInt = X509::from_pem(&Bytes::from(caChain[0].clone())).unwrap();
				let caRoot = X509::from_pem(&Bytes::from(caChain[1].clone())).unwrap();

				let key = PKey::private_key_from_pem(&Bytes::from(grpcCert.private_key.clone())).unwrap();
				let mut peer = HttpPeer::new(serviceEP, true, ctx.service.clone());
				let mut peerOpts = PeerOptions::new();

				peer.client_cert_key = Some(Arc::new(CertKey::new(vec![cert], key)));
				peerOpts.alpn = ALPN::H2;

				peerOpts.ca = Some(Arc::new(Box::new([caInt.clone(), caRoot.clone()])));
				peer.options = peerOpts;

				Ok(Box::new(peer))
			} else {
				let peer = Box::new(HttpPeer::new(serviceEP, false, "".to_string()));
				Ok(peer)
			}
		} else {
			let mut h = ResponseHeader::build(503, None).unwrap();
			let _ = h.insert_header("content-type", "text/html");
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

	async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Self::CTX) -> FailToProxy
	where
		Self::CTX: Send + Sync,
	{
		let uri: Uri;

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
			return FailToProxy { error_code: 503, can_reuse_downstream: false };
		} else if ctx.redirectToStaticServer {
			let h = ResponseHeader::build(404, None).unwrap();
			session.write_response_header(Box::new(h), true).await.unwrap();
			session
				.write_response_body(Some(Bytes::from(String::into_bytes(not_found_error(uri.path().to_string())))), true)
				.await
				.unwrap();
			session.set_keepalive(None);

			return FailToProxy { error_code: 404, can_reuse_downstream: false };
		}
		error!("error: {}, ctx: {:?}", e, e.context);

		return FailToProxy { error_code: 502, can_reuse_downstream: false };
	}
}
