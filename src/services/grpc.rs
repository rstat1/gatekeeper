/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/
use hyper::server::conn::http2::Builder;
use hyper_util::{
	rt::{TokioExecutor, TokioIo},
	service::TowerToHyperService,
};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{
	rustls::{
		server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
		sign::CertifiedKey,
		RootCertStore, ServerConfig,
	},
	TlsAcceptor,
};
use tonic::{body::boxed, service::Routes, Request, Response, Status};
use tower::{ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use super::{config_svc::ConfigServiceImpl, endpoint_manager::EndpointManagerImpl, types::Empty};
use crate::{
	grpc_fd_set,
	pki::CertManagerSvc,
	services::v1::{config_service_server::*, endpoint_manager_server::*, *},
	SYSTEM_CONFIG,
};

pub(crate) const FD_SET: &[u8] = grpc_fd_set!("descriptors");

#[derive(Clone)]
pub struct GRPCServer {
	certVerifier: Option<Arc<GRPCServerCertVerifier>>,
	apiSvcImpl: Arc<ConfigServiceImpl>,
	svcRegistryImpl: Arc<EndpointManagerImpl>,
}

impl GRPCServer {
	pub async fn InitAndServe(sr: Arc<EndpointManagerImpl>, api: Arc<ConfigServiceImpl>, certSvc: Arc<CertManagerSvc>) {
		let srv = GRPCServer { svcRegistryImpl: Arc::clone(&sr), apiSvcImpl: Arc::clone(&api), certVerifier: Some(Arc::new(GRPCServerCertVerifier { certSvc: certSvc.clone() })) };
		let svcReg = EndpointManagerServer::new(srv.clone());
		let api = ConfigServiceServer::new(srv.clone());
		let reflectSvc = tonic_reflection::server::Builder::configure().register_encoded_file_descriptor_set(FD_SET).build_v1().unwrap();

		let serverCert = certSvc.GetExistingServiceCert("gatekeeper".to_string()).await.unwrap();
		let verifier = srv.certVerifier.unwrap().clone();
		let mut roots = RootCertStore::empty();
		let clientCACert = serverCert.ca_cert.clone();
		let certDer: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(clientCACert.as_bytes()).map(|result| result.unwrap()).collect();

		roots.add_parsable_certificates(certDer);

		let mut tls = ServerConfig::builder()
			.with_client_cert_verifier(WebPkiClientVerifier::builder(roots.into()).build().unwrap())
			.with_cert_resolver(verifier);

		tls.alpn_protocols = vec![b"h2".to_vec()];

		let svc = Routes::builder().add_service(svcReg).add_service(reflectSvc).add_service(api).to_owned();
		let http = Builder::new(TokioExecutor::new());
		let listener = TcpListener::bind(SYSTEM_CONFIG.apiServerAddr.clone().unwrap_or("0.0.0.0:2000".to_string())).await.unwrap();
		let tls_acceptor = TlsAcceptor::from(Arc::new(tls));

		loop {
			let (conn, _) = match listener.accept().await {
				Ok(incoming) => incoming,
				Err(e) => {
					eprintln!("Error accepting connection: {e}");
					continue;
				}
			};

			let http = http.clone();
			let tls_acceptor = tls_acceptor.clone();
			let svc = svc.clone().routes();

			tokio::spawn(async move {
				match tls_acceptor.accept(conn).await {
					Ok(conn) => {
						let svc = ServiceBuilder::new().service(svc);
						http.serve_connection(TokioIo::new(conn), TowerToHyperService::new(svc.map_request(|req: http::Request<_>| req.map(boxed))))
							.await
							.unwrap();
					}
					Err(err) => error!("{}", err),
				}
			});
		}
	}
}

#[tonic::async_trait]
impl EndpointManager for GRPCServer {
	async fn register_service_endpoint(&self, request: Request<NewServiceEndpoint>) -> Result<Response<Empty>, Status> {
		let reply = Empty {};

		let svcInfo = request.get_ref();
		match self.svcRegistryImpl.RegisterServiceEndpoint(&svcInfo) {
			Ok(_) => Ok(Response::new(reply)),
			Err(e) => Err(Status::new(tonic::Code::InvalidArgument, format!("error registering service endpoint: {}", e))),
		}
	}
	async fn get_service_endpoint(&self, request: Request<ServiceEndpointRequest>) -> Result<Response<ServiceEndpointResponse>, Status> {
		let req = request.get_ref();

		let name = match &req.name {
			Some(service_endpoint_request::Name::Service(n)) => n,
			Some(service_endpoint_request::Name::Endpoint(n)) => n,
			None => &"".to_string(),
		};

		if name == "" {
			return Err(Status::new(tonic::Code::InvalidArgument, "no name specified"));
		}

		let ep = self.svcRegistryImpl.GetServiceEndpoint(name);
		if let Some(ep) = ep {
			Ok(Response::new(ServiceEndpointResponse { endpoint: ep.to_string() }))
		} else {
			Err(Status::new(tonic::Code::InvalidArgument, format!("unknown service: {}", name)))
		}
	}
}
#[tonic::async_trait]
impl ConfigService for GRPCServer {
	async fn new_service(&self, request: Request<NewServiceRequest>) -> Result<Response<ServiceCredentials>, Status> {
		let svc = request.get_ref();
		match self.apiSvcImpl.NewService(svc.svc_details.as_ref().unwrap(), &svc.parent_namespace).await {
			Ok(r) => {
				self.svcRegistryImpl.AddServiceToKnownList(&svc.svc_details.as_ref().unwrap());

				Ok(Response::new(r.1))
			}
			Err(e) => {
				if e == "already exists" {
					Err(Status::new(tonic::Code::AlreadyExists, format!("service already exists")))
				} else {
					Err(Status::new(tonic::Code::Unknown, e))
				}
			}
		}
	}
	async fn new_namespace(&self, request: Request<NewNamespaceRequest>) -> Result<Response<Id>, Status> {
		match self.apiSvcImpl.NewNamespace(request.get_ref().domain.as_ref().unwrap()).await {
			Ok(id) => Ok(Response::new(Id { id })),
			Err(e) => {
				if e == "already exists" {
					Err(Status::new(tonic::Code::AlreadyExists, format!("service namespace already exists")))
				} else {
					Err(Status::new(tonic::Code::Unknown, e))
				}
			}
		}
	}
	async fn new_route_alias(&self, request: Request<AliasRequest>) -> Result<Response<Empty>, Status> {
		match self.apiSvcImpl.NewRouteAlias(request.get_ref()).await {
			Ok(_) => Ok(Response::new(Empty {})),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_service_by_id(&self, request: Request<Id>) -> Result<Response<Service>, Status> {
		match self.apiSvcImpl.GetServiceByID(&request.get_ref().id).await {
			Ok(Some(svc)) => Ok(Response::new(svc)),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "servicw with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_service_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<Service>, tonic::Status> {
		match self.apiSvcImpl.GetServiceByName(&request.get_ref().name).await {
			Ok(Some(svc)) => Ok(Response::new(svc)),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "servicw with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_namespace_by_id(&self, request: Request<Id>) -> Result<Response<Namespace>, Status> {
		match self.apiSvcImpl.GetNamespaceByID(&request.get_ref().id).await {
			Ok(Some(d)) => Ok(Response::new(d)),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "service with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_namespace_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<Namespace>, tonic::Status> {
		match self.apiSvcImpl.GetNamespaceByName(&request.get_ref().name).await {
			Ok(Some(d)) => Ok(Response::new(d)),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "service with the provided name doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn delete_namespace(&self, request: Request<Id>) -> Result<Response<Empty>, Status> {
		match self.apiSvcImpl.DeleteNamespace(&request.get_ref().id).await {
			Ok(r) => {
				if r {
					Ok(Response::new(Empty::default()))
				} else {
					Err(Status::new(tonic::Code::Unknown, "nothing was deleted. invalid id?"))
				}
			}
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn delete_service(&self, request: Request<Id>) -> Result<Response<Empty>, Status> {
		match self.apiSvcImpl.DeleteService(&request.get_ref().id).await {
			Ok(r) => {
				if r {
					Ok(Response::new(Empty::default()))
				} else {
					Err(Status::new(tonic::Code::Unknown, "nothing was deleted. invalid id?"))
				}
			}
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn request_cert_renewal(&self, request: Request<Id>) -> Result<Response<ServiceCredentials>, Status> {
		match self.svcRegistryImpl.ServiceIdToName(&request.get_ref().id) {
			Ok(name) => match self.apiSvcImpl.RenewServiceCredentials(&name).await {
				Ok(newCreds) => Ok(Response::new(newCreds)),
				Err(_) => Err(Status::new(tonic::Code::Unknown, "nothing generated. invalid id?")),
			},
			Err(_) => Err(Status::new(tonic::Code::Unknown, "invalid id")),
		}
	}
}
#[derive(Debug)]
pub struct GRPCServerCertVerifier {
	certSvc: Arc<CertManagerSvc>,
}
impl ResolvesServerCert for GRPCServerCertVerifier {
	fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		match self.certSvc.GetExistingServiceCertBlocking("gatekeeper".to_string()) {
			Some(c) => {
				debug!("resolved creds...");
				let clientCACert = c.ca_cert.clone();
				let serverCA = CertificateDer::from_pem_slice(c.certificate.as_bytes()).unwrap();

				let mut certChain: Vec<CertificateDer<'static>> = Vec::default();
				let mut certDer: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(clientCACert.as_bytes()).map(|result| result.unwrap()).collect();
				certChain.push(serverCA);
				certChain.append(&mut certDer);

				let key = PrivateKeyDer::from_pem_slice(c.private_key.as_bytes());

				let key = CertifiedKey::from_der(certChain, key.unwrap(), &CryptoProvider::get_default().unwrap());
				if key.is_err() {
					error!("key.unwrap_err: {}", key.unwrap_err());
					return None;
				}

				Some(Arc::new(key.unwrap()))
			}
			None => {
				error!("failed to get gatekeeper cert from cache");
				None
			}
		}
	}

	fn only_raw_public_keys(&self) -> bool {
		false
	}
}
