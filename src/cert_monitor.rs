/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use tracing::{
	span::{Attributes, Id, Record},
	Dispatch, Event, Metadata, Subscriber,
};

use tracing_subscriber::{filter::LevelFilter, layer::*, prelude::*, Layer};

pub struct CertificateMonitorLayer;

impl CertificateMonitorLayer {
	pub fn new() -> Self {
		Self {}
	}
}

impl<S: Subscriber> Layer<S> for CertificateMonitorLayer {
	fn enabled(&self, metadata: &Metadata<'_>, ctx: Context<'_, S>) -> bool {
		true
	}

	fn event_enabled(&self, _event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
		true
	}

	fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
		if event.metadata().target() == "cert_monitor" {
			println!("{:?}", event)
		}
		if event.metadata().target() == "ep_monitor" {
			println!("{:?}", event)
		}
	}
}
