/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

#[macro_export]
macro_rules! grpc_include {
	($package: tt) => {
		include!(concat!("proto/generated", concat!("/", $package, ".rs")));
	};
}

#[macro_export]
macro_rules! grpc_fd_set {
	($package: tt) => {
		include_bytes!(concat!("proto/generated", concat!("/", $package, ".bin")))
	};
}

pub mod api;
pub mod cert_svc;
pub mod endpoint_manager;
pub mod grpc;

pub mod v1 {
	grpc_include!("gatekeeper.api.v1");
	grpc_include!("gatekeeper.endpoint_manager.v1");
}
pub mod types {
	grpc_include!("gatekeeper.services.types");
}
