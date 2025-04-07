/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{net::SocketAddr, sync::Arc};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::error;

use super::{config_svc::ConfigServiceImpl, endpoint_manager::EndpointManagerImpl, types::Empty};
use crate::grpc_fd_set;
use crate::services::v1::config_service_server::*;
use crate::services::v1::endpoint_manager_server::*;
use crate::services::v1::*;
use crate::vault::Certificate as VaultCertificate;

pub(crate) const FD_SET: &[u8] = grpc_fd_set!("descriptors");

#[derive(Clone)]
pub struct GRPCServer {
	apiSvcImpl: Arc<ConfigServiceImpl>,
	svcRegistryImpl: Arc<EndpointManagerImpl>,
}

impl GRPCServer {
	pub async fn InitAndServe(addr: SocketAddr, sr: Arc<EndpointManagerImpl>, api: Arc<ConfigServiceImpl>, serverCert: Arc<VaultCertificate>) {
		let srv = GRPCServer { svcRegistryImpl: Arc::clone(&sr), apiSvcImpl: Arc::clone(&api) };
		let svcReg = EndpointManagerServer::new(srv.clone());
		let api = ConfigServiceServer::new(srv.clone());
		let reflectSvc = tonic_reflection::server::Builder::configure().register_encoded_file_descriptor_set(FD_SET).build_v1().unwrap();

		let serverID = Identity::from_pem(serverCert.certificate.clone(), serverCert.private_key.clone());
		let clientCACert = serverCert.issuing_ca.clone();
		let clientCACert = Certificate::from_pem(clientCACert);

		let tls = ServerTlsConfig::new().identity(serverID).client_ca_root(clientCACert);

		match Server::builder()
			.tls_config(tls)
			.unwrap()
			.add_service(svcReg)
			.add_service(api)
			.add_service(reflectSvc)
			.serve(addr)
			.await
		{
			Ok(_) => {}
			Err(e) => {
				error!("{:?}", e)
			}
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
	async fn new_service(&self, request: Request<NewServiceRequest>) -> Result<Response<NewServiceResponse>, Status> {
		let svc = request.get_ref();
		match self.apiSvcImpl.NewService(svc.svc_details.as_ref().unwrap(), &svc.parent_service_domain).await {
			Ok(r) => {
				let ca_chain = r.1.ca_chain.unwrap();
				let x = ca_chain.iter().fold(String::new(), |acc, i| acc + "\n" + i);
				let sc = ServiceCredentials { ca_cert: x, certificate: r.1.certificate, expires_at: r.1.expiration.unwrap_or(0), issuer_cert: r.1.issuing_ca, private_key: r.1.private_key };
				Ok(Response::new(NewServiceResponse { id: r.0, cert: Some(sc) }))
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
	async fn new_service_domain(&self, request: Request<NewDomainRequest>) -> Result<Response<Id>, Status> {
		match self.apiSvcImpl.NewServiceDomain(request.get_ref().domain.as_ref().unwrap()).await {
			Ok(id) => Ok(Response::new(Id { id })),
			Err(e) => {
				if e == "already exists" {
					Err(Status::new(tonic::Code::AlreadyExists, format!("service domain already exists")))
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
			Ok(Some(svc)) => Ok(Response::new(Service {
				id: svc.id,
				is_frost_service: svc.isFrostSvc,
				name: svc.name,
				internal: svc.internal,
				allows_external_device_login: false,
				security_policies: svc.securityPolices.unwrap_or(Vec::default()),
			})),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "servicw with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_service_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<Service>, tonic::Status> {
		match self.apiSvcImpl.GetServiceByName(&request.get_ref().name).await {
			Ok(Some(svc)) => Ok(Response::new(Service {
				id: svc.id,
				is_frost_service: svc.isFrostSvc,
				name: svc.name,
				internal: svc.internal,
				allows_external_device_login: false,
				security_policies: svc.securityPolices.unwrap_or(Vec::default()),
			})),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "servicw with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_domain_by_id(&self, request: Request<Id>) -> Result<Response<ServiceDomain>, Status> {
		match self.apiSvcImpl.GetDomainByID(&request.get_ref().id).await {
			Ok(Some(d)) => Ok(Response::new(ServiceDomain {
				base: d.base,
				attached_services: d.services,
				gatekeeper_managed_certs: d.gatekeeperManagedCerts,
				domain_security_policies: d.securityPolicies.unwrap_or(Vec::default()),
			})),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "service with the provided ID doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn get_domain_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<ServiceDomain>, tonic::Status> {
		match self.apiSvcImpl.GetDomainByName(&request.get_ref().name).await {
			Ok(Some(d)) => Ok(Response::new(ServiceDomain {
				base: d.base,
				attached_services: d.services,
				gatekeeper_managed_certs: d.gatekeeperManagedCerts,
				domain_security_policies: d.securityPolicies.unwrap_or(Vec::default()),
			})),
			Ok(None) => Err(Status::new(tonic::Code::NotFound, "service with the provided name doesn't not exist")),
			Err(e) => Err(Status::new(tonic::Code::Unknown, e)),
		}
	}
	async fn delete_domain(&self, request: Request<Id>) -> Result<Response<Empty>, Status> {
		match self.apiSvcImpl.DeleteDomain(&request.get_ref().id).await {
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
}
