/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

use gatekeeper::services::static_file_server::StaticFileServer;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::services::listening::Service as ListeningService;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use gatekeeper::data::*;
use gatekeeper::gw::*;
use gatekeeper::services::api::APIServiceImpl;
use gatekeeper::services::cert_svc::CertManagerSvc;
use gatekeeper::services::endpoint_manager::EndpointManagerImpl;
use gatekeeper::services::grpc::GRPCServer;
use gatekeeper::vault::{Certificate, DBCredentials, VaultClient};

fn main() {
	tracing_subscriber::fmt::init();
	info!("starting gatekeeper...");

	let db: Arc<DataStore>;
	let dbCreds: DBCredentials;
	let apiImpl: APIServiceImpl;
	let vault: Arc<VaultClient>;
	let acme: Arc<CertManagerSvc>;
	let conf: SystemConfiguration;
	let apiServiceCert: Certificate;
	let srImpl: Arc<EndpointManagerImpl>;
	let svcsList: Vec<GatekeeperService>;
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

	let async_db_init = async { DataStore::new(&dbCreds.username, &dbCreds.password, &conf.mongoEndpoint, conf.collectionName, vault.clone()).await };
	match rt.block_on(async_db_init) {
		Ok(ds) => {
			debug!("mongodb client init");
			db = ds
		}
		Err(e) => panic!("{:?}", e),
	}

	let async_get_svcs = async { db.GetAllServices().await };
	match rt.block_on(async_get_svcs) {
		Ok(list) => svcsList = list,
		Err(e) => panic!("{:?}", e),
	}

	let async_ac_init = async { CertManagerSvc::new(vault.clone()).await };
	match rt.block_on(async_ac_init) {
		Ok(ac) => acme = Arc::new(ac),
		Err(e) => {
			panic!("cert_svc init failed: {}", e)
		}
	}

	let async_sri_init = async { EndpointManagerImpl::new(db.clone(), svcsList.clone(), conf.healthCheckInterval).await };
	match rt.block_on(async_sri_init) {
		Ok(sri) => srImpl = sri,
		Err(e) => panic!("{:?}", e),
	}

	apiImpl = APIServiceImpl::new(db.clone(), acme.clone());

	let dynamic_cert = DynamicCert::new();
	let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert).unwrap();
	tls_settings.enable_h2();
	// tls_settings.enable_ocsp_stapling();

	let certPath = Path::new("certs/svcs/gatekeeper.cert");

	if !certPath.exists() {
		let async_get_server_cert = async { acme.GenerateServiceCert(&"gatekeeper".to_string()).await };
		match rt.block_on(async_get_server_cert) {
			Ok(cert) => apiServiceCert = cert,
			Err(e) => panic!("{:?}", e),
		}
	} else {
		let async_get_server_cert = async { acme.GetExistingServiceCert("gatekeeper".to_string()).await };
		match rt.block_on(async_get_server_cert) {
			Ok(cert) => apiServiceCert = cert,
			Err(e) => panic!("{:?}", e),
		}
	}

	let mut staticServer: ListeningService<StaticFileServer> = StaticFileServer::new().Service();
	staticServer.add_tcp(conf.staticFileServerAddr.clone().unwrap_or("0.0.0.0:10000".to_string()).as_str());

	let mut prometheus_service_http = ListeningService::prometheus_http_service();
	prometheus_service_http.add_tcp("127.0.0.1:6150");

	let mut proxy = pingora_proxy::http_proxy_service(
		&server.configuration,
		ReverseProxy::new(srImpl.clone(), svcsList, &conf.staticFileServerAddr.unwrap_or("0.0.0.0:10000".to_string())),
	);
	proxy.add_tls_with_settings(&conf.tlsListenerAddr, None, tls_settings);

	std::thread::spawn(move || {
		let grpcRT = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		let grpcTask = async {
			let addr = "0.0.0.0:2000".parse().unwrap();
			GRPCServer::InitAndServe(addr, srImpl.clone(), Arc::new(apiImpl), apiServiceCert).await;
		};
		grpcRT.block_on(grpcTask);
	});

	server.add_service(proxy);
	server.add_service(staticServer);
	server.add_service(prometheus_service_http);
	server.run_forever();
}
