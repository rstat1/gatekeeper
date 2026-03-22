# Gatekeeper

> **DISCLAIMER:** This project is highly experimental and not production-ready. It is intended only for internal, non-Internet-facing use at this time, and was primarily created as a vechicle for me (rstat1, project founder) to learn Rust.

Gatekeeper is a Rust-based dynamic gateway / reverse proxy service with:
- mTLS-enabled proxy via `pingora` (HTTP/2 + ACME dynamic certs)
- gRPC control plane for service registration and endpoints
- MongoDB data persistence for namespaces and services
- Redis caching for fast lookups
- Vault (OpenBao hasn't been tested, but may work) integration for secrets (DB creds, Cloudflare API token, service certificates)
- Cloudflare API integration for DNS / certificate event hooks. No other DNS provider is supported at this time.
- Static file service + API and external device auth endpoints
- Certificate status API (revocation/health checks)

## Configuration

Put a JSON file named `gatekeeper_config` next to the executable that matches the following, replacing the provided values with your own

```json
{
  "vaultAddr": "https://vault.example.local:8200",
  "dbAddr": "mongodb.example.local:27017",
  "dbName": "gatekeeper",
  "redisAddr": "redis://127.0.0.1:6379",
  "listenOnTLS": "0.0.0.0:443",
  "listenOn": "0.0.0.0:80",
  "acmeContactEmail": "admin@example.com",
  "vaultCAName": "my-ca-name",
  "pingIntervalSecs": 30,
  "staticFileServerAddr": "0.0.0.0:10000",
  "devAuthServerAddr": "0.0.0.0:10001",
  "certStatusServerAddr": "0.0.0.0:10002",
  "apiServerAddr": "0.0.0.0:10003",
  "devMode": true,
  "certCheckInterval": 600
}
```
```listenOn``` and ```listenOnTLS``` specify an IP:Port combo on which Gatekeeper will listen for incoming HTTP and HTTPS traffic respectively.

```staticFileServerAddr```, ```devAuthServerAddr``` and ```certStatusServerAddr``` are optional config values, that are probably best left unset and kept to their defaults.

```apiServiceAddr``` specifies the address Gatekeeper's API service will reachable at.

```certCheckInterval``` is the time in seconds between checks for service and domain (namespace) certificate expiration

```pingIntervalSecs``` is the time in seconds between liveness checks for connected endpoints. If a connected endpoint crashes, or is otherwise stopped for some reason this is how long it'll take to be removed from the list of endpoints Gatekeeper will direct a particular service's traffic to.

```devMode``` exists as a setting to make sure a development instance and a production instance can use the same Vault and MongoDB servers without trampling over each other's data. It basically just causes a "dev" or "-dev" suffix to the names for Vault and MongoDB stuff.

### Vault expectations
Your vault instnace MUST have the following:

  * A ```database``` secrets engine configured to generate credentials for MongoDB. How to configure this is beyond the scope of this document.
  * A ```PKI``` secrets engine configured to generate certificates for services. This is where the certs used for the mTLS functionality come from. How to configure this is beyond the scope of this document.
  * A ```KV``` secrets engine configured under the ```gatekeeper``` path for storing various types of credentials and API tokens. This is where the cloudflare token will live.
