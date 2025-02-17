/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use std::{env, sync::Arc};
use tokio::time::Duration;
use tracing::error;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};

struct TokenRenewer {
    client: Arc<GatekeeperVaultClient>,
}

pub struct GatekeeperVaultClient {
    client: VaultClient,
}

pub struct DBCredentials {
    pub username: String,
    pub password: String,
}

impl GatekeeperVaultClient {
    pub async fn new(vault_ep: &String) -> Result<Arc<Self>, String> {
        match env::var_os("INITTOKEN") {
            Some(t) => {
                if let Ok(init_token) = t.into_string() {
                    let c: VaultClient = VaultClient::new(
                        VaultClientSettingsBuilder::default()
                            .address(vault_ep)
                            .token(init_token)
                            .verify(false)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                    let vault = Arc::new(Self { client: c });

                    match vault.client.lookup().await {
                        Ok(t) => {
                            if t.ttl == 0 {
                                println!("token has no ttl?");
                            } else {
                                vault.start_renewal_timer(t.ttl).await;
                            }
                        }
                        Err(e) => match e {
                            vaultrs::error::ClientError::APIError { code, errors } => {
                                error!("APIError: code: {}, errors: {:?}", code, errors)
                            }
                            vaultrs::error::ClientError::FileNotFoundError { path } => {
                                error!("FileNotFoundError: source: {}", path)
                            }
                            vaultrs::error::ClientError::FileReadError { source, path } => {
                                error!("FileReadError source: {}, path: {}", source, path)
                            }
                            vaultrs::error::ClientError::FileWriteError { source, path } => {
                                error!("FileWriteError source: {}, path: {}", source, path)
                            }
                            vaultrs::error::ClientError::InvalidLoginMethodError => {
                                error!("invalid login method")
                            }
                            vaultrs::error::ClientError::JsonParseError { source } => {
                                error!("JSON parse error: {}", source)
                            }
                            vaultrs::error::ClientError::ParseCertificateError { source, path } => {
                                error!("source: {}, path: {}", source, path)
                            }
                            vaultrs::error::ClientError::ResponseEmptyError => {
                                error!("ResponseEmptyError")
                            }
                            vaultrs::error::ClientError::ResponseDataEmptyError => {
                                error!("ResponseDataEmptyError")
                            }
                            vaultrs::error::ClientError::ResponseWrapError => {
                                error!("ResponseWrapError")
                            }
                            vaultrs::error::ClientError::RestClientBuildError { source } => {
                                error!("RestClientBuildError: source: {}", source)
                            }
                            vaultrs::error::ClientError::RestClientError { source } => {
                                error!("RestClientError: source: {}", source)
                            }
                            vaultrs::error::ClientError::WrapInvalidError => {
                                error!("WrapInvalidError")
                            }
                            vaultrs::error::ClientError::InvalidUpdateParameter => {
                                error!("InvalidUpdateParameter")
                            }
                        },
                    }
                    Ok(vault)
                } else {
                    Err("invalid init token".to_string())
                }
            }
            None => Err("no init token".to_string()),
        }
    }
    pub async fn get_db_credentials(&self) -> Result<DBCredentials, String> {
        let db_creds =
            vaultrs::database::role::creds(&self.client, "database", "platform-service").await;
        match db_creds {
            Ok(creds) => Ok(DBCredentials {
                username: creds.username,
                password: creds.password,
            }),
            Err(e) => match e {
                vaultrs::error::ClientError::APIError { code, errors } => {
                    Err(format!("APIError: code: {}, errors: {:?}", code, errors))
                }
                vaultrs::error::ClientError::FileNotFoundError { path } => {
                    Err(format!("FileNotFoundError: source: {}", path))
                }
                vaultrs::error::ClientError::FileReadError { source, path } => {
                    Err(format!("FileReadError source: {}, path: {}", source, path))
                }
                vaultrs::error::ClientError::FileWriteError { source, path } => {
                    Err(format!("FileWriteError source: {}, path: {}", source, path))
                }
                vaultrs::error::ClientError::InvalidLoginMethodError => {
                    Err("invalid login method".to_string())
                }
                vaultrs::error::ClientError::JsonParseError { source } => {
                    Err(format!("JSON parse error: {}", source))
                }
                vaultrs::error::ClientError::ParseCertificateError { source, path } => {
                    Err(format!("source: {}, path: {}", source, path))
                }
                vaultrs::error::ClientError::ResponseEmptyError => {
                    Err("ResponseEmptyError".to_string())
                }
                vaultrs::error::ClientError::ResponseDataEmptyError => {
                    Err("ResponseDataEmptyError".to_string())
                }
                vaultrs::error::ClientError::ResponseWrapError => {
                    Err("ResponseWrapError".to_string())
                }
                vaultrs::error::ClientError::RestClientBuildError { source } => {
                    Err(format!("RestClientBuildError: source: {}", source))
                }
                vaultrs::error::ClientError::RestClientError { source } => {
                    Err(format!("RestClientError: source: {}", source))
                }
                vaultrs::error::ClientError::WrapInvalidError => {
                    Err("WrapInvalidError".to_string())
                }
                vaultrs::error::ClientError::InvalidUpdateParameter => {
                    Err("InvalidUpdateParameter".to_string())
                }
            },
        }
    }
    async fn start_renewal_timer(self: &Arc<Self>, ttl: u64) {
        let renewer = Arc::new(TokenRenewer {
            client: Arc::clone(&self),
        });
        renewer.start_renewal(ttl);
    }
    async fn renew_token(&self) {}
}

impl TokenRenewer {
    pub fn start_renewal(self: &Arc<Self>, token_ttl: u64) {
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(token_ttl)).await;
                self_clone.client.renew_token().await;
            }
        });
    }
}
