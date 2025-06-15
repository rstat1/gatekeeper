/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

use core::panic;
use pingora::{listeners::tls::TlsSettings, prelude::*, services::listening::Service as ListeningService};
use std::{env, fs, path::Path, str::FromStr, sync::Arc};
use tokio::sync::watch::Receiver;
use tracing::{debug, info, warn};
use tracing_subscriber::{filter::Targets, fmt::Subscriber, prelude::*};

use gatekeeper::{
	cloudflare_api::*,
	data::*,
	gw::*,
	pki::CertManagerSvc,
	services::{
		config_svc::ConfigServiceImpl, endpoint_manager::EndpointManagerImpl, ext_device::ExternalDeviceManager, grpc::GRPCServer, static_file_server::StaticFileServer,
		v1::Service,
	},
	vault::{Certificate, DBCredentials, VaultClient},
	SYSTEM_CONFIG,
};

fn main() {
	let devMode: bool;
	let db: Arc<DataStore>;
	let dbCreds: DBCredentials;
	let apiImpl: ConfigServiceImpl;
	let vault: Arc<VaultClient>;
	let cmSvc: Arc<CertManagerSvc>;
	let apiServiceCert: Arc<Certificate>;
	let srImpl: Arc<EndpointManagerImpl>;
	let svcsList: Vec<Service>;
	let cache: Arc<CacheService>;
	let cfAPI: Arc<CloudflareAPIClient>;
	let certUpdatesReceiver: Receiver<(Certificate, String)>;
	let mut server = Server::new(None).unwrap();
	let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();

	let targets = match env::var("RUST_LOG") {
		Ok(var) => Targets::from_str(&var)
			.map_err(|e| {
				eprintln!("Ignoring `RUST_LOG={:?}`: {}", var, e);
			})
			.unwrap_or_default(),
		Err(env::VarError::NotPresent) => Targets::new().with_default(Subscriber::DEFAULT_MAX_LEVEL),
		Err(e) => {
			eprintln!("Ignoring `RUST_LOG`: {}", e);
			Targets::new().with_default(Subscriber::DEFAULT_MAX_LEVEL)
		}
	};

	tracing_subscriber::registry().with(targets).with(tracing_subscriber::fmt::layer()).init();

	info!("starting gatekeeper...");

	server.bootstrap();

	devMode = SYSTEM_CONFIG.devMode.unwrap_or(false);

	if devMode {
		info!("...in dev mode");
	}

	let path = Path::new("certs/svcs");
	if !path.exists() {
		fs::create_dir_all(path).unwrap();
	}

	let async_vc_init = async { VaultClient::new(&SYSTEM_CONFIG.vaultEndpoint, devMode).await };
	match rt.block_on(async_vc_init) {
		Ok(c) => {
			info!("vault client init");
			vault = c
		}
		Err(e) => panic!("{:?}", e),
	}

	let get_db_creds = async { vault.GetDBCredentials(devMode).await };
	match rt.block_on(get_db_creds) {
		Ok(dbs) => {
			debug!("got db creds");
			dbCreds = dbs
		}
		Err(e) => panic!("{:?}", e),
	}

	let get_cf_api_token = async { vault.ReadValueFromKV("cf_api_token", "gatekeeper").await };
	match rt.block_on(get_cf_api_token) {
		Ok(token) => {
			let value = token.as_object().unwrap();
			cfAPI = CloudflareAPIClient::new(value["token"].as_str().unwrap().to_string(), value["zoneID"].as_str().unwrap().to_string());
			info!("cfapi client init")
		}
		Err(e) => panic!("{:?}", e),
	}

	let async_db_init = async {
		DataStore::new(
			&dbCreds.username,
			&dbCreds.password,
			&SYSTEM_CONFIG.mongoEndpoint,
			&SYSTEM_CONFIG.collectionName,
			vault.clone(),
			&SYSTEM_CONFIG.redisServerAddress,
			devMode,
		)
		.await
	};
	match rt.block_on(async_db_init) {
		Ok(ds) => {
			info!("mongodb client init");
			db = ds
		}
		Err(e) => panic!("{:?}", e),
	}

	let async_get_svcs = async { db.GetAllServices().await };
	match rt.block_on(async_get_svcs) {
		Ok(list) => {
			debug!("got service list");
			svcsList = list
		}
		Err(e) => panic!("{:?}", e),
	}

	match CacheService::new() {
		Ok(client) => {
			cache = Arc::new(client);
		}
		Err(e) => panic!("{}", e),
	}

	let async_ac_init = async { CertManagerSvc::new(vault.clone(), cfAPI.clone(), cache.clone()).await };
	match rt.block_on(async_ac_init) {
		Ok(ac) => {
			info!("cmsvc init");
			cmSvc = ac.0;
			certUpdatesReceiver = ac.1
		}
		Err(e) => {
			panic!("cert_svc init failed: {}", e)
		}
	}

	let dynamic_cert = DynamicCert::new(cmSvc.clone());
	let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert).unwrap();
	tls_settings.enable_h2();
	// tls_settings.enable_ocsp_stapling();

	let certPath = Path::new("certs/svcs/gatekeeper.cert");

	if !certPath.exists() {
		let async_get_server_cert = async { cmSvc.GenerateServiceCert(&"gatekeeper".to_string(), false).await };
		match rt.block_on(async_get_server_cert) {
			Ok(cert) => apiServiceCert = Arc::new(cert),
			Err(e) => panic!("{:?}", e),
		}
	} else {
		let async_check_cert_expiry = async { cmSvc.IsCertificateExpired(&"gatekeeper".to_string(), false).await };
		match rt.block_on(async_check_cert_expiry) {
			Ok(ac) => {
				if ac {
					warn!("gatekeeper API service cert has expired, forcing renewal...");
					let _ = fs::remove_file("certs/svcs/gatekeeper.cert");
					let async_get_server_cert = async { cmSvc.GenerateServiceCert(&"gatekeeper".to_string(), false).await };
					match rt.block_on(async_get_server_cert) {
						Ok(cert) => apiServiceCert = Arc::new(cert),
						Err(e) => panic!("{:?}", e),
					}
				} else {
					let async_get_server_cert = async { cmSvc.GetExistingServiceCert("gatekeeper".to_string(), false).await };
					match rt.block_on(async_get_server_cert) {
						Ok(cert) => apiServiceCert = Arc::new(cert),
						Err(e) => panic!("{:?}", e),
					}
				}
			}
			Err(e) => {
				panic!("cert expiry check failed: {}", e)
			}
		}
	}

	let async_sri_init = async { EndpointManagerImpl::new(db.clone(), svcsList.clone(), SYSTEM_CONFIG.healthCheckInterval, apiServiceCert.clone(), certUpdatesReceiver).await };
	match rt.block_on(async_sri_init) {
		Ok(sri) => {
			info!("epmgr init");
			srImpl = sri
		}
		Err(e) => panic!("{:?}", e),
	}
	apiImpl = ConfigServiceImpl::new(db.clone(), cmSvc.clone(), srImpl.clone());

	let mut staticServer: ListeningService<StaticFileServer> = StaticFileServer::Service();
	staticServer.add_tcp(SYSTEM_CONFIG.staticFileServerAddr.clone().unwrap_or("0.0.0.0:10000".to_string()).as_str());

	let mut devAuthServer: ListeningService<ExternalDeviceManager> = ExternalDeviceManager::Service(db.clone(), cmSvc.clone(), apiServiceCert.expiration, srImpl.clone());
	devAuthServer.add_tcp(SYSTEM_CONFIG.devAuthServerAddr.clone().unwrap_or("0.0.0.0:10001".to_string()).as_str());

	let mut prometheus_service_http = ListeningService::prometheus_http_service();
	prometheus_service_http.add_tcp("127.0.0.1:6150");

	let mut proxy = pingora_proxy::http_proxy_service(
		&server.configuration,
		ReverseProxy::new(
			srImpl.clone(),
			&SYSTEM_CONFIG.staticFileServerAddr.clone().unwrap_or("0.0.0.0:10000".to_string()),
			&apiServiceCert,
			&SYSTEM_CONFIG.devAuthServerAddr.clone().unwrap_or("0.0.0.0:10001".to_string()),
		),
	);
	proxy.add_tls_with_settings(&SYSTEM_CONFIG.tlsListenerAddr, None, tls_settings);

	std::thread::spawn(move || {
		let grpcRT = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		let grpcTask = async {
			let addr = SYSTEM_CONFIG.apiServerAddr.clone().unwrap_or("0.0.0.0:2000".to_string()).parse().unwrap();
			GRPCServer::InitAndServe(addr, srImpl.clone(), Arc::new(apiImpl), apiServiceCert.clone()).await;
		};
		grpcRT.block_on(grpcTask);
	});

	server.add_service(proxy);
	server.add_service(staticServer);
	server.add_service(devAuthServer);
	server.add_service(prometheus_service_http);
	server.run_forever();
}
