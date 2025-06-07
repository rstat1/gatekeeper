/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

//This is stupid. I shouldn't need to clutter up the code like this to disable stupid
//messages about formatting that shouldn't be complier warnings.
#![allow(nonstandard_style)]

pub mod data;
pub mod gw;
pub mod services;
pub mod vault;
pub mod cloudflare_api;

const ERROR_PAGE: &'static str = include_str!("assets/error_page.html");

fn generate_err_page(code: String, error: String, err_details: String, reason: String) -> String {
    let mut page = ERROR_PAGE.to_string();

    page = page.replace("##ERROR##", &error);
    page = page.replace("##ERROR_CODE##", &code);
    page = page.replace("##ERROR_REASON##", &reason);
    page = page.replace("##ERROR_DESCRIPTION##", &err_details);

    return page;
}
pub(crate) fn no_endpoint_err() -> String {
    generate_err_page(
        "503".to_string(),
        "Service Unavailable".to_string(),
        "There are no endpoints registered for this service.".to_string(),
        "This is likely do to a configuration issue or because all available instances of the service have crashed.".to_string(),
    )
}
pub(crate) fn not_found_error(routeOrSvc: String) -> String {
    generate_err_page(
        "404".to_string(),
        "Not Found".to_string(),
        format!("Unknown route or service: <code>{}</code>", routeOrSvc),
        "The requested URL is unknown to this server".to_string(),
    )
}

pub struct ErrorPage;

impl ErrorPage {
	
}
