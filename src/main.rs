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
use tracing::{debug, info};

use gatekeeper::data::*;
use gatekeeper::gw::ReverseProxy;
use gatekeeper::vault::{DBCredentials, GatekeeperVaultClient};

fn main() {
    tracing_subscriber::fmt::init();
    info!("starting gatekeeper...");
    let mut server = Server::new(None).unwrap();
    let conf: SystemConfiguration;
    let vault: Arc<GatekeeperVaultClient>;
    let db: DataStore;
    let dbCreds: DBCredentials;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    server.bootstrap();

    let conf_file = std::fs::read_to_string("gatekeeper_config");
    match conf_file {
        Ok(file) => {
            conf = serde_json::from_str(&file).unwrap();
        }
        Err(e) => panic!("{:?}", e),
    }

    let async_vc_init = async { GatekeeperVaultClient::new(&conf.vaultEndpoint).await };
    match rt.block_on(async_vc_init) {
        Ok(c) => vault = c,
        Err(e) => panic!("{:?}", e),
    }

    info!("vault client init");

    let async_db_init = async { vault.get_db_credentials().await };
    match rt.block_on(async_db_init) {
        Ok(dbs) => dbCreds = dbs,
        Err(e) => panic!("{:?}", e),
    }

    match DataStore::new(&dbCreds.username, &dbCreds.password, &conf.mongoEndpoint, conf.collectionName) {
        Ok(ds) => db = ds,
        Err(e) => panic!("{:?}", e),
    }

    debug!("mongodb client init");

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, ReverseProxy::new(db));
    proxy.add_tcp("0.0.0.0:8080");
    server.add_service(proxy);
    server.run_forever();
}
