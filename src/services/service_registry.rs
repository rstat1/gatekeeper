/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

#![allow(dead_code)]

use crate::data::{self, Domain};
use std::{
	collections::HashMap,
	net::SocketAddr,
	sync::{Arc, Mutex},
};
use tracing::{debug, error, warn};

pub struct EndpointManagerImpl {
	domains: Vec<Domain>,
	db: Arc<data::DataStore>,
	epMap: Mutex<HashMap<String, Vec<SocketAddr>>>,
}

impl EndpointManagerImpl {
	pub async fn new(data: Arc<data::DataStore>) -> Result<Self, String> {
		match data.GetDomains().await {
			Ok(d) => Ok(EndpointManagerImpl { db: data, domains: Vec::from(d), epMap: Mutex::new(HashMap::new()) }),
			Err(e) => Err(e.to_string()),
		}
	}

	pub fn IsValidDomain(&self, domain: &String) -> bool {
		for d in &self.domains {
			if d.base == *domain {
				return true;
			}
		}
		warn!("didn't find a valid Domain for {}", domain);
		false
	}

	pub fn RegisterServiceEndpoint(&self, name: &String, ep: &String) {
		let epMap = self.epMap.try_lock();

		match epMap {
			Ok(mut m) => {
				if let Some(eps) = m.get_mut(name) {
					debug!("added endpoint {} to service {}", ep, name);
					eps.push(ep.parse().unwrap());
				} else {
					debug!("added new service {} at {}", name, ep);
					m.insert(name.clone(), vec![ep.parse().unwrap()]);
				}
			}
			Err(e) => {
				error!("{:?}", e)
			}
		}
	}
	pub fn GetServiceEndpoint(&self, name: &String) -> Option<SocketAddr> {
		let epMap = self.epMap.try_lock();
		match epMap {
			Ok(m) => {
				if let Some(eps) = m.get(name) {
					if eps.len() > 1 {
						//TODO: Randome selection?
						return Some(eps[0].clone());
					}
					return Some(eps[0].clone());
				}
				return None;
			}
			Err(e) => {
				error!("{:?}", e)
			}
		}
		None
	}
}
