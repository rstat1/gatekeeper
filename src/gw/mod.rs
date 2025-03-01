/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]



use crate::data::DataStore;

pub mod gateway;

pub struct ReverseProxy {
    dataStore: DataStore,
    serviceDomainNames: Vec<String>,
}

impl ReverseProxy {
    pub fn new(db: DataStore) -> Self {
        match db.GetDomainNames() {
            Ok(domains) => ReverseProxy { dataStore: db, serviceDomainNames: domains },
            Err(e) => {
                panic!("{:?}", e)
            }
        }
    }
}