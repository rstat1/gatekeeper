/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use async_trait::async_trait;

use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tracing::debug;

use crate::data::DataStore;

#[async_trait]
impl ProxyHttp for crate::gw::ReverseProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let host = session.get_header("Host");

        debug!("{:?}", session.get_header("Host"));

        if let Some(host) = host {
            if self.serviceDomainNames.iter().any(|sd| sd == host.to_str().unwrap()) {
                let urlParts: Vec<&str> = host.to_str().unwrap().split(".").collect();

                return Ok(false);
            }
        }

        let h = ResponseHeader::build(400, None).unwrap();
        session.write_response_header(Box::new(h), true).await?;
        session.write_response_body(Some(Bytes::from_static(b"go away!\n")), true).await?;
        session.set_keepalive(None);
        return Ok(true);
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        //TODO: Not hardcoded service url.
        let peer = Box::new(HttpPeer::new(("127.0.0.1", 1013), false, "".to_string()));
        Ok(peer)
    }

    async fn response_filter(&self, _session: &mut Session, _upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Ok(())
    }
}


