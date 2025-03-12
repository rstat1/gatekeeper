/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

use gatekeeper::data::*;
use gatekeeper::gw::*;
use gatekeeper::services::api::APIServiceImpl;
use gatekeeper::services::cert_svc::CertManagerSvc;
use gatekeeper::services::grpc::GRPCServer;
use gatekeeper::services::service_registry::ServiceRegistryImpl;
use gatekeeper::vault::{DBCredentials, VaultClient};

fn main() {
	tracing_subscriber::fmt::init();
	info!("starting gatekeeper...");

	let db: Arc<DataStore>;
	let dbCreds: DBCredentials;
	let apiImpl: APIServiceImpl;
	let vault: Arc<VaultClient>;
	let acme: Arc<CertManagerSvc>;
	let conf: SystemConfiguration;
	let srImpl: Arc<ServiceRegistryImpl>;
	let mut server = Server::new(None).unwrap();
	let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();

	server.bootstrap();

	let conf_file = std::fs::read_to_string("gatekeeper_config");
	match conf_file {
		Ok(file) => {
			conf = serde_json::from_str(&file).unwrap();
		}
		Err(e) => panic!("{:?}", e),
	}

	let path = Path::new("certs/svcs");
	if !path.exists() {
		fs::create_dir_all(path).unwrap();
	}

	let async_vc_init = async { VaultClient::new(&conf.vaultEndpoint).await };
	match rt.block_on(async_vc_init) {
		Ok(c) => {
			debug!("vault client init");
			vault = c
		}
		Err(e) => panic!("{:?}", e),
	}

	let get_db_creds = async { vault.GetDBCredentials().await };
	match rt.block_on(get_db_creds) {
		Ok(dbs) => dbCreds = dbs,
		Err(e) => panic!("{:?}", e),
	}

	let async_db_init = async { DataStore::new(&dbCreds.username, &dbCreds.password, &conf.mongoEndpoint, conf.collectionName).await };
	match rt.block_on(async_db_init) {
		Ok(ds) => {
			debug!("mongodb client init");
			db = ds
		}
		Err(e) => panic!("{:?}", e),
	}

	let async_ac_init = async { CertManagerSvc::new(vault.clone()).await };
	match rt.block_on(async_ac_init) {
		Ok(ac) => acme = Arc::new(ac),
		Err(e) => {
			panic!("cert_svc init failed: {}", e)
		}
	}

	let async_sri_init = async { ServiceRegistryImpl::new(db.clone(), acme.clone()).await };
	match rt.block_on(async_sri_init) {
		Ok(sri) => srImpl = Arc::new(sri),
		Err(e) => panic!("{:?}", e),
	}

	apiImpl = APIServiceImpl::new(db.clone(), vault.clone());

	let dynamic_cert = DynamicCert::new();
	let tls_settings = TlsSettings::with_callbacks(dynamic_cert).unwrap();

	let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, ReverseProxy::new(srImpl.clone()));
	proxy.add_tcp(&conf.listenerAddr);
	proxy.add_tls_with_settings(&conf.tlsListenerAddr, None, tls_settings);

	std::thread::spawn(move || {
		let grpcRT = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		let grpcTask = async {
			let addr = "0.0.0.0:2000".parse().unwrap();
			GRPCServer::InitAndServe(addr, srImpl.clone(), Arc::new(apiImpl)).await;
		};
		grpcRT.block_on(grpcTask);
	});

	server.add_service(proxy);
	server.run_forever();
}
