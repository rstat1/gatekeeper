/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use super::{api::APIServiceImpl, service_registry::ServiceRegistryImpl, types::Empty};
use crate::services::v1::api_service_server::*;
use crate::services::v1::service_registry_server::*;
use crate::services::v1::*;
use crate::{grpc_fd_set, grpc_include};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{debug, error};
use tracing_subscriber::fmt::format;

pub(crate) const FD_SET: &[u8] = grpc_fd_set!("descriptors");

#[derive(Clone)]
pub struct GRPCServer {
    apiSvcImpl: Arc<APIServiceImpl>,
    svcRegistryImpl: Arc<ServiceRegistryImpl>,
}

impl GRPCServer {
    pub async fn InitAndServe(addr: SocketAddr, sr: Arc<ServiceRegistryImpl>, api: Arc<APIServiceImpl>) {
        let srv = GRPCServer {
            svcRegistryImpl: Arc::clone(&sr),
            apiSvcImpl: Arc::clone(&api),
        };
        let svcReg = ServiceRegistryServer::new(srv.clone());
        let api = ApiServiceServer::new(srv.clone());
        let reflectSvc = tonic_reflection::server::Builder::configure().register_encoded_file_descriptor_set(FD_SET).build_v1().unwrap();
        match Server::builder().add_service(svcReg).add_service(api).add_service(reflectSvc).serve(addr).await {
            Ok(_) => {}
            Err(e) => {
                error!("{:?}", e)
            }
        }
    }
}

#[tonic::async_trait]
impl ServiceRegistry for GRPCServer {
    async fn register_service(&self, request: Request<NewService>) -> Result<Response<Empty>, Status> {
        let reply = Empty {};

        let svcInfo = request.get_ref();
        self.svcRegistryImpl.RegisterServiceEndpoint(&svcInfo.service_name, &svcInfo.endpoint);

        Ok(Response::new(reply))
    }
    async fn get_service_endpoint(&self, request: Request<ServiceEndpointRequest>) -> Result<Response<ServiceEndpointResponse>, Status> {
        let req = request.get_ref();
        let ep = self.svcRegistryImpl.GetServiceEndpoint(&req.name);
        if let Some(ep) = ep {
            Ok(Response::new(ServiceEndpointResponse { endpont: ep.to_string() }))
        } else {
            Err(Status::new(tonic::Code::InvalidArgument, format!("unknown service: {}", req.name)))
        }
    }
}
#[tonic::async_trait]
impl ApiService for GRPCServer {
    async fn new_service(&self, request: Request<NewServiceRequest>) -> Result<Response<Id>, Status> {
        let svc = request.get_ref();
        match self.apiSvcImpl.NewService(svc.svc_details.as_ref().unwrap(), &svc.parent_service_domain).await {
            Ok(id) => Ok(Response::new(Id { id })),
            Err(e) => {
                if e == "already exists" {
                    Err(Status::new(tonic::Code::Unknown, format!("service already exists")))
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
                    Err(Status::new(tonic::Code::Unknown, format!("service domain already exists")))
                } else {
                    Err(Status::new(tonic::Code::Unknown, e))
                }
            }
        }
    }
    async fn get_service_by_id(&self, request: Request<Id>) -> Result<Response<Service>, Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method new_services is not implemented"))
    }
    async fn get_domain_by_id(&self, request: Request<Id>) -> Result<Response<ServiceDomain>, Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method get_domain_by_id is not implemented"))
    }
    async fn get_domain_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<DomainByNameResponse>, tonic::Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method get_domain_by_name is not implemented"))
    }
    async fn get_service_by_name(&self, request: Request<ByNameRequest>) -> Result<Response<ServiceByNameResponse>, tonic::Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method get_service_by_name is not implemented"))
    }
    async fn delete_domain(&self, request: Request<Id>) -> Result<Response<Empty>, Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method delete_domain is not implemented"))
    }
    async fn delete_service(&self, request: Request<Id>) -> Result<Response<Empty>, Status> {
        Err(Status::new(tonic::Code::Unimplemented, "method delete_service is not implemented"))
    }
}
