/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use async_trait::async_trait;
use http::{Response, StatusCode, Uri};
use pingora::{apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service};
use std::path::Path;

use tracing::error;

use crate::not_found_error;

pub struct StaticFileServer;

impl StaticFileServer {
	pub fn new() -> Self {
		return StaticFileServer {};
	}
	pub fn Service() -> Service<StaticFileServer> {
		Service::new("Static File Server".to_string(), StaticFileServer)
	}
	fn isFilePath(&self, path: String) -> (bool, &str) {
		let ext: Vec<_> = path.split(".").collect();

		let contentType = match ext[1] {
			".css" => "text/css",
			".js" => "application/javascript",
			".png" => "image/png",
			".jpg" => "image/jpeg",
			".svg" => "image/svg+xml",
			_ => "",
		};

		let isFileType = (path.ends_with(".css") || path.ends_with(".js") || path.ends_with(".png") || path.ends_with(".jpg") || path.ends_with(".svg")) == true;

		(isFileType, contentType)
	}
}

#[async_trait]
impl ServeHttp for StaticFileServer {
	async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
		let uri: Uri;
		let path: String;
		let mut mimeType = "text/html";
		let mut sc: StatusCode = StatusCode::OK;
		let mut resp_body: Vec<u8> = Vec::default();

		if http_session.is_http2() {
			uri = http_session.as_http2().unwrap().req_header().uri.clone();
			path = uri.path().to_string();
		} else {
			uri = http_session.get_header("Host").unwrap().to_str().unwrap().parse().unwrap();
			path = http_session.req_header().uri.to_string();
		}

		let host = uri.authority().unwrap().to_string();
		let urlParts: Vec<&str> = host.splitn(2, ".").collect();

		let webDirPathStr = format!("web/{}", urlParts[0]);
		let webDirPath = Path::new(webDirPathStr.as_str());
		if webDirPath.exists() {
			let (isFile, fileType) = self.isFilePath(path.clone());
			if isFile {
				mimeType = fileType;
				let file = std::fs::read("path");
				match file {
					Ok(f) => {
						resp_body = f;
					}
					Err(e) => {
						sc = StatusCode::NOT_FOUND;
						error!("{}", e);
					}
				}
			} else {
				let index = std::fs::read_to_string(format!("{}/index.html", webDirPathStr));

				match index {
					Ok(f) => {
						resp_body = Vec::from(f.as_bytes());
					}
					Err(e) => {
						sc = StatusCode::NOT_FOUND;
						error!("{}", e);
					}
				}
			}
		} else {
			sc = StatusCode::NOT_FOUND;
		}

		if sc == StatusCode::NOT_FOUND {
			resp_body = Vec::from(not_found_error(path.clone()))
		}

		Response::builder()
			.status(sc)
			.header(http::header::CONTENT_TYPE, mimeType)
			.header(http::header::CONTENT_LENGTH, resp_body.len())
			.body(resp_body)
			.unwrap()
	}
}
