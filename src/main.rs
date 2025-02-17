/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

use pingora::prelude::*;
use std::sync::Arc;
use tracing::info;

use gatekeeper::data::*;
use gatekeeper::gw::APIGateway;
use gatekeeper::vault::GatekeeperVaultClient;

fn main() {
    tracing_subscriber::fmt::init();
    info!("starting gatekeeper...");
    let mut server = Server::new(None).unwrap();
    let mut mongoDBEp: String = "".to_string();
    let conf: SystemConfiguration;
    let vault: Arc<GatekeeperVaultClient>;
    let db: DataStore;
    let rt = tokio::runtime::Runtime::new().unwrap();

    server.bootstrap();

    let conf_file = std::fs::read_to_string("gatekeeper_config");
    match conf_file {
        Ok(file) => {
            conf = serde_json::from_str(&file).unwrap();
        }
        Err(e) => panic!("{:?}", e),
    }

    let async_vc_init = async { GatekeeperVaultClient::new(&conf.vault_endpoint).await };
    match rt.block_on(async_vc_init) {
        Ok(c) => vault = c,
        Err(e) => panic!("{:?}", e),
    }

    let async_db_init = async {
        let mongo_creds = vault.get_db_credentials().await;
        match mongo_creds {
            Ok(creds) => {
                mongoDBEp = format!("mongodb://{}:{}@{}/{}?authsource={}", creds.username, creds.password, conf.mongo_endpoint, conf.collection_name, conf.collection_name);
                DataStore::new(&mongoDBEp).await
            }
            Err(e) => panic!("{:?}", e),
        }
    };
    match rt.block_on(async_db_init) {
        Ok(dbs) => db = dbs,
        Err(e) => panic!("{:?}", e),
    }

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, APIGateway::new(db));
    proxy.add_tcp("0.0.0.0:8080");
    server.add_service(proxy);
    server.run_forever();
}
