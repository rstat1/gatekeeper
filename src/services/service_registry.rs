/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{net::SocketAddr, sync::Arc};

use redis::Commands;
use service_registry_server::{ServiceRegistry, ServiceRegistryServer};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{debug, error};

include!("proto/service_registry/generated/gatekeeper.service_registry.v1.rs");
const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("proto/service_registry/generated/svcregistry_descriptor.bin");

#[derive(Debug)]
pub struct SRImpl {
    redisClient: redis::Client,
}

#[derive(Debug)]
pub struct ServiceRegistryService {
    svcRegistryImpl: Arc<SRImpl>,
}

impl ServiceRegistryService {
    pub async fn InitAndServe(addr: SocketAddr, sr: Arc<SRImpl>) {
        let svcReg = ServiceRegistryServer::new(ServiceRegistryService { svcRegistryImpl: Arc::clone(&sr) });
        let reflectSvc = tonic_reflection::server::Builder::configure().register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET).build_v1().unwrap();
        Server::builder().add_service(svcReg).add_service(reflectSvc).serve(addr).await;
    }
}

#[tonic::async_trait]
impl ServiceRegistry for ServiceRegistryService {
    async fn register_service(&self, request: Request<NewService>) -> Result<Response<Empty>, Status> {
        let reply = Empty {};

        let svcInfo = request.get_ref();
        self.svcRegistryImpl.RegisterService(&svcInfo.service_name, &svcInfo.endpoint);

        Ok(Response::new(reply))
    }
}

impl SRImpl {
    pub fn new(redisAddr: &String) -> Self {
        let rc = redis::Client::open(redisAddr.clone());
        match rc {
            Ok(c) => SRImpl { redisClient: c },
            Err(e) => panic!("{:?}", e),
        }
    }
    pub fn RegisterService(&self, name: &String, ep: &String) {
        let svcKey = format!("gksr:svcep:{}", name);
        let mut con = self.redisClient.get_connection().unwrap();

        redis::cmd("SET").arg(svcKey).arg(ep).exec(&mut con).expect("failed register service");
        debug!("added new service {} at endpoint {}", name, ep);
    }
}
