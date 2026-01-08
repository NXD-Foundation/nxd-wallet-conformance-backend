# ITB+ Issuer / Verifier Service

A comprehensive Node.js implementation of **OpenID for Verifiable Credential Issuance (OID4VCI) v1.0** and **OpenID for Verifiable Presentations (OpenID4VP) v1.0**, designed as a flexible testbed for credential issuance and verification workflows.

## Overview

This project provides a unified backend service that implements:

- **Credential Issuer**: Full OID4VCI v1.0 implementation supporting multiple credential formats (SD-JWT, JWT VC, mDL/PID)
- **Credential Verifier**: Full OpenID4VP v1.0 implementation supporting multiple client identification schemes and response modes
- **Test Wallet**: Companion wallet-holder implementation for exercising all issuer and verifier capabilities

The service is **configuration-driven**, allowing new credential types and verifier scenarios to be added primarily through JSON configuration files rather than code changes.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Issuer Capabilities (OID4VCI v1.0)](#issuer-capabilities-oid4vci-v10)
- [Verifier Capabilities (OpenID4VP v1.0)](#verifier-capabilities-openid4vp-v10)
- [Wallet Client Capabilities](#wallet-client-capabilities)
- [Using the Wallet Client](#using-the-wallet-client)
- [References](#references)

## Quick Start

### Prerequisites

- Node.js (v18 or higher)
- Redis server (for session and credential storage)
- npm or yarn

### Installation and Setup

1. **Install dependencies**:
```bash
cd rfc-issuer-v1
npm install
```

2. **Start Redis** (if not already running):
```bash
redis-server
```

3. **Start the issuer/verifier service**:
```bash
node server.js
```

The service will start on `http://localhost:3000` by default.

4. **Optional: Set custom server URL** (for HTTPS or tunneling):
```bash
SERVER_URL="https://your-public-url.example.com" node server.js
```

### Test with Wallet Client

In a separate terminal, start the wallet client:

```bash
cd wallet-client
npm install
npm start
```

The wallet client will start on `http://localhost:4000` by default.

### Example: Issue a Credential

```bash
# Using wallet client CLI
cd wallet-client
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-no-code --credential VerifiablePortableDocumentA2SDJWT
```

## Configuration

The service is driven by JSON configuration files:

- **`data/issuer-config.json`**: Defines credential configurations, issuance profiles, and OID4VCI capabilities
- **`data/verifier-config.json`**: Defines OpenID4VP request templates, presentation definitions, and verifier endpoints
- **`data/oauth-config.json`**: OAuth 2.0 / OpenID Connect metadata for authorization server

Additional artifacts:

- **OpenAPI description** (`openapi/conformance-backend-endpoint.yaml`): Exposes key endpoints for conformance tooling
- **Well-known metadata**: Published via `routes/metadataroutes.js` at standard `.well-known` endpoints

## Architecture

The issuer/verifier service is built on **Express.js** and follows a modular route-based architecture:

### Core Server (`server.js`)

- **Express application**: Main HTTP server running on port 3000 (configurable)
- **Middleware stack**:
  - **Body parsing**: Supports JSON, URL-encoded, and raw JWT (`application/jwt`) payloads (up to 10MB)
  - **Session-based logging**: Console log interception with Redis-backed session context
  - **Request/response logging**: Comprehensive request/response logging with session correlation
  - **Session context management**: Automatic session ID extraction from query params, body, or URL params

### Route Modules

#### Issuance Routes (`routes/issue/`)

- **`preAuthSDjwRoutes.js`**: Pre-authorized code flow endpoints
  - `GET /offer-tx-code`, `GET /offer-no-code`: SD-JWT credential offers (with/without transaction code)
  - `GET /haip-offer-tx-code`: HAIP profile credential offers
  - `GET /credential-offer-tx-code/:id`, `GET /credential-offer-no-code/:id`: Credential offer configuration retrieval
- **`codeFlowSdJwtRoutes.js`**: Authorization code flow endpoints for SD-JWT
  - `GET /offer-code-sd-jwt`: Static authorization code flow offers
  - `GET /offer-code-sd-jwt-dynamic`: Dynamic authorization code flow offers (requires VP)
  - `GET /offer-code-defered`: Authorization code flow with deferred issuance
  - `POST /par`, `POST /authorize/par`: Push Authorization Request (RFC 9126)
  - `GET /authorize`: OAuth 2.0 authorization endpoint
  - Dynamic VP request endpoints for various client ID schemes
- **`sharedIssuanceFlows.js`**: Shared OID4VCI v1.0 endpoints
  - `POST /token_endpoint`: Token endpoint (supports both grant types)
  - `POST /credential`: Credential endpoint (immediate issuance)
  - `POST /credential_deferred`: Deferred credential endpoint (polling)
  - `POST /nonce`: Nonce endpoint (`c_nonce` generation)
  - `POST /notification`: Notification endpoint (credential lifecycle events)
- **`vciStandardRoutes.js`**: Standardized VCI endpoint
  - `GET /vci/offer`: Unified endpoint supporting both flows via query parameters

#### Verification Routes (`routes/verify/`)

- **`verifierRoutes.js`**: Main OpenID4VP verifier routes
  - `GET /vp-request/*`: VP request generation for various use cases
  - `POST /direct_post_vp`, `POST /direct_post_vp_jwt`: VP response handling
  - Presentation definition and DCQL query processing
- **`vpStandardRoutes.js`**: Standardized VP endpoint
  - `GET /vp/request`: Unified VP request endpoint
- **`didRoutes.js`**: DID-based verifier routes (`did:web` client identification)
- **`didJwkRoutes.js`**: DID JWK-based verifier routes (`did:jwk` client identification)
- **`x509Routes.js`**: X.509 certificate-based verifier routes (`x509_san_dns`, `x509_san_uri`, `x509_hash`)
- **`mdlRoutes.js`**: mDL/PID-specific verification routes
- **`verifierAttestationRoutes.js`**: Verifier attestation (VA-JWT) routes

#### Use Case Routes

- **`codeFlowJwtRoutes.js`**: JWT VC authorization code flow routes
- **`jwtVcRoutes.js`**: JWT VC pre-authorized flow routes
- **`pidroutes.js`**: Personal Identification Document (PID) specific routes
- **`passportRoutes.js`**: e-Passport routes
- **`boardingPassRoutes.js`**: Ferry boarding pass routes
- **`educationalRoutes.js`**: Education ID routes
- **`paymentRoutes.js`**: Payment-specific routes
- **`receiptsRoutes.js`**: Receipt credential routes
- **`batchRequestRoutes.js`**: Batch credential request handling
- **`didweb.js`**: DID Web resolution routes
- **`redirectUriRoutes.js`**: Redirect URI-based client identification routes

#### Metadata & Logging Routes

- **`metadataroutes.js`**: Well-known metadata endpoints
  - `/.well-known/openid-credential-issuer`: Credential issuer metadata
  - `/.well-known/oauth-authorization-server`: Authorization server metadata
  - `/.well-known/openid-configuration`: OpenID Connect configuration
  - `/.well-known/jwt-vc-issuer`: JWT VC issuer metadata
- **`loggingRoutes.js`**: Session logging and status endpoints
  - `GET /issueStatus`: Session status check
  - `GET /logs/:sessionId`: Retrieve session logs

### Services

- **`services/cacheServiceRedis.js`**: Redis-backed session and state management
  - Pre-authorized session storage
  - Authorization code flow session storage
  - Deferred issuance transaction tracking
  - Nonce management (`c_nonce` storage and validation)
  - Console log interception and session-based logging
  - Poll time tracking for deferred issuance
- **`services/cacheService.js`**: Legacy in-memory cache (fallback)

### Utilities

- **`utils/credGenerationUtils.js`**: Credential generation based on format (SD-JWT, JWT VC, mDL)
- **`utils/cryptoUtils.js`**: Cryptographic utilities (JWK conversion, nonce generation, DID resolution, VP request building)
- **`utils/sdjwtUtils.js`**: SD-JWT specific utilities (signing, verification, salt generation)
- **`utils/tokenUtils.js`**: Token generation utilities (access tokens, ID tokens, VP tokens)
- **`utils/routeUtils.js`**: Route helper utilities (session management, QR code generation, error handling)
- **`utils/mdlVerification.js`**: mDL/PID verification utilities
- **`utils/personasUtils.js`**: Persona data management
- **`utils/vpHeplers.js`**: Verifiable Presentation helper functions

## Issuer Capabilities (OID4VCI v1.0)

This issuer implements **OpenID for Verifiable Credential Issuance (OID4VCI) v1.0** with the following specification-compliant capabilities:

### Authorization Flows

#### Pre-Authorized Code Flow
Per OID4VCI v1.0 Section 4.1.1:

- **Grant type**: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- **Transaction code (PIN) support**: Optional `user_pin_required` with configurable PIN length and input mode
- **URL schemes**: Supports both `openid-credential-offer://` (standard) and `haip://` (HAIP profile)
- **Credential offer delivery**: Via deep links or credential offer URIs
- **Authorization details**: Supports `authorization_details` parameter for credential selection in token request
- **Session management**: Redis-backed session storage with configurable TTL

#### Authorization Code Flow
Per OID4VCI v1.0 Section 4.1.2:

- **Grant type**: `authorization_code`
- **PKCE support**: Full RFC 7636 PKCE (Proof Key for Code Exchange) with `S256` code challenge method
- **Dynamic credential requests**: Supports dynamic credential requests requiring Verifiable Presentations
- **Push Authorization Request (PAR)**: Full RFC 9126 PAR support via `/par` and `/authorize/par` endpoints
- **Authorization endpoint**: Standard OAuth 2.0 authorization endpoint with `response_type=code`
- **Client identification**: Multiple `client_id_scheme` values supported (see below)
- **Issuer state**: Supports `issuer_state` parameter for state management

### Credential Formats

The issuer supports the following credential formats per OID4VCI v1.0:

- **`dc+sd-jwt`** (SD-JWT for Verifiable Credentials): Selective disclosure JWT credentials
  - Uses `@sd-jwt/sd-jwt-vc` library for SD-JWT generation
  - Supports selective disclosure of claims
  - Key-binding JWT support for presentation
- **`jwt_vc_json`**: Standard JWT Verifiable Credentials (W3C VC Data Model)
  - Plain JWT-based credentials with `vc` claim
  - Supports various signing algorithms (ES256, RS256)
- **`mso_mdoc`**: ISO/IEC 18013-5:2021 mDL (mobile Driving License) format
  - Uses `@auth0/mdl` library for mDL generation
  - CBOR-encoded credentials with COSE Sign1 signatures
  - Device key binding support

### Proof-of-Possession (PoP)

Per OID4VCI v1.0 Section 7.2, the issuer implements:

- **Proof format validation**: Enforces `proofs` (plural) format per V1.0 specification
  - Rejects legacy `proof` (singular) format with clear error messages
  - Requires exactly one proof type in `proofs` object
- **Proof type**: `jwt` (JWT-based proof)
- **Proof signing algorithms**: Validates against `proof_signing_alg_values_supported` from credential configuration
  - Supports `ES256`, `ES384`, `ES512`, `EdDSA` (configurable per credential type)
- **Public key resolution**:
  - **JWK in header**: Direct JWK embedding (`jwk` claim in JWT header)
  - **DID methods**: `did:key:`, `did:jwk:`, `did:web:` with key resolution
    - `did:key`: Resolves via DID key-to-JWKS conversion
    - `did:jwk`: Extracts JWK directly from DID identifier
    - `did:web`: Fetches DID document from `.well-known/did.json` or path-based resolution
  - **Key identifier**: `kid`-based key resolution for issuer-managed keys
- **Proof validation**: Full signature verification, nonce validation, and claim validation
  - Validates `iss` claim (required for authorization code flow)
  - Validates `aud` claim (must match credential issuer identifier)
  - Validates `nonce` claim (must match issued `c_nonce`)
- **Nonce management**: `c_nonce` generation and validation with automatic refresh on proof failure
  - Nonce stored in Redis with expiration
  - Nonce deleted after successful proof validation
  - Nonce validation prioritized before signature verification for better error reporting

### Cryptographic Binding Methods

The issuer supports multiple cryptographic binding methods per credential configuration:

- **`jwk`**: JWK-based binding with public key in proof JWT header
- **`did:key`**: DID-based binding using `did:key:` method
- **`did:jwk`**: DID-based binding using `did:jwk:` method  
- **`did:web`**: DID-based binding using `did:web:` method with DID document resolution

### Client Identification Schemes

For authorization code flows, the issuer supports multiple `client_id_scheme` values:

- **`redirect_uri`**: Client identified by redirect URI (no client authentication required)
- **`x509_san_dns`**: Client identified by X.509 certificate Subject Alternative Name (DNS)
- **`did:web`**: Client identified by DID Web (`did:web:` method)
- **`did:jwk`**: Client identified by DID JWK (`did:jwk:` method)
- **`payment`**: Payment-specific client identification scheme

### Credential Signing

The issuer supports multiple signature types for credential issuance:

- **`x509`**: X.509 certificate-based signing (ES256 with certificate chain in `x5c` header)
- **`jwk`**: JWK-based signing with embedded public key in JWT header
- **`kid-jwk`**: Key identifier-based signing with issuer-managed key resolution
- **`did:web`**: DID Web-based signing with key resolution from DID document

### Deferred Issuance

Per OID4VCI v1.0 Section 9.2:

- **Deferred credential endpoint**: `/credential_deferred` for polling credential status
- **Transaction ID**: Unique `transaction_id` returned in `202 Accepted` response
- **Polling interval**: Configurable polling interval with rate limiting
- **Status tracking**: Session-based status tracking for deferred credentials
- **Error handling**: Supports `authorization_pending` and `slow_down` error codes

### Demonstrating Proof-of-Possession (DPoP)

Per RFC 9449:

- **DPoP support**: Optional DPoP header in token requests
- **Token binding**: Access tokens bound to DPoP public key via `cnf.jkt` claim
- **Token type**: Returns `DPoP` token type when DPoP proof is validated
- **Fallback**: Falls back to `Bearer` token type when DPoP is not provided
- **JWT thumbprint**: Calculates JWK thumbprint (SHA-256) for token confirmation

### Wallet Attestation

Per EUDI Wallet specifications (TS3):

- **Wallet Instance Attestation (WIA)**: Optional validation of WIA JWT in token requests
  - Validates WIA signature, claims (`iss`, `aud`, `iat`, `exp`, `jti`), and expiration
  - Extracts WIA from `client_assertion` parameter
  - Graceful degradation: continues without attestation if not provided (logs warning)
- **Wallet Unit Attestation (WUA)**: Optional validation of WUA JWT in credential requests
  - Validates WUA signature, claims, and expiration
  - Extracts WUA from proof JWT header `key_attestation` claim
  - Validates `attested_keys` array and `eudi_wallet_info` structure
  - Graceful degradation: continues without attestation if not provided (logs warning)

### Notification Endpoint

Per OID4VCI v1.0 Section 11:

- **Notification events**: Supports credential lifecycle events:
  - `credential_accepted`: Credential successfully accepted by wallet
  - `credential_failure`: Credential issuance or acceptance failed
  - `credential_deleted`: Credential deleted by wallet
- **Authentication**: Bearer token authentication required
- **Session tracking**: Updates session status based on notification events

### Nonce Endpoint

Per OID4VCI v1.0 Section 8.1:

- **`c_nonce` generation**: Fresh nonce generation for proof-of-possession
- **Nonce expiration**: Configurable expiration time (default: 86400 seconds)
- **Cache control**: `Cache-Control: no-store` header for nonce responses
- **Nonce storage**: Redis-backed nonce storage with expiration

### Verifiable Presentation Support (Dynamic Credential Requests)

For authorization code flows with dynamic credential requests:

- **OpenID4VP support**: Full OpenID for Verifiable Presentations v1.0 support
- **VP request formats**: JWT-based VP requests with various client identification schemes
- **Response modes**: Supports `direct_post` for VP responses
- **Presentation definition**: Supports Presentation Exchange (PEX) and DCQL query formats
- **ID token support**: Supports `id_token` response type for PID issuance flows

### Credential Request Validation

Per OID4VCI v1.0 Section 7.1:

- **Credential identifier**: Supports both `credential_configuration_id` and `credential_identifier`
  - Validates that exactly one is provided (not both, not neither)
- **Proof format**: Enforces `proofs` (plural) object with exactly one proof type
  - Rejects legacy `proof` (singular) format
  - Supports `proofs.jwt` as string or array (uses first element if array)
- **Error messages**: Provides detailed error messages with specification references
  - Includes received vs expected values for debugging
  - References specific OID4VCI v1.0 sections in error responses

### Standardized VCI Endpoint

- **`GET /vci/offer`**: Unified endpoint supporting both flows via query parameters
  - `flow`: `authorization_code` or `pre_authorized_code`
  - `tx_code_required`: `true` or `false`
  - `credential_type`: e.g., `urn:eu.europa.ec.eudi:pid:1`, `org.iso.18013.5.1.mDL`
  - `credential_format`: `sd-jwt` or `mso_mdoc`
  - `signature_type`: `x509`, `jwk`, `kid-jwk`, or `did-web`
  - `url_scheme`: `haip` (optional, for HAIP links)

## Verifier Capabilities (OpenID4VP v1.0)

This verifier implements **OpenID for Verifiable Presentations (OpenID4VP) v1.0** with the following specification-compliant capabilities:

### Authorization Request Formats

#### JWT Authorization Request (JAR)
Per RFC 9101, the verifier supports JWT-secured authorization requests:

- **Request by value**: JWT embedded directly in `request` parameter
- **Request by reference**: JWT referenced via `request_uri` parameter
- **Request URI methods**: Supports both `GET` and `POST` methods for request URI resolution
- **JWT signing algorithms**: 
  - `ES256` (ECDSA using P-256 and SHA-256) for EC keys
  - `RS256` (RSA with SHA-256) for RSA keys (legacy)
  - `none` (unsigned) for `redirect_uri` client identification scheme
- **Request URI storage**: Stores request URIs with expiration (default: 90 seconds)
- **Request validation**: Validates JWT signature, claims, and expiration

### Client Identification Schemes

The verifier supports multiple `client_id_scheme` values per OpenID4VP v1.0:

- **`redirect_uri`**: Client identified by redirect URI (no client authentication required)
  - Used for simple flows without cryptographic client authentication
  - Request JWT can be unsigned (`alg: none`)
- **`x509_san_dns`**: Client identified by X.509 certificate Subject Alternative Name (DNS)
  - Validates certificate SAN DNS against `client_id`
  - Supports certificate chain validation
- **`x509_san_uri`**: Client identified by X.509 certificate Subject Alternative Name (URI)
  - Validates certificate SAN URI against `client_id`
- **`x509_hash`**: Client identified by X.509 certificate hash (SHA-256)
  - Validates certificate hash against `client_id`
- **`did:web`**: Client identified by DID Web (`did:web:` method)
  - Resolves DID document from `.well-known/did.json` or path-based resolution
  - Validates verification methods in DID document
- **`did:jwk`**: Client identified by DID JWK (`did:jwk:` method)
  - Extracts JWK directly from DID identifier
  - Validates public key from DID
- **`verifier_attestation`**: Client identified by Verifier Attestation JWT (VA-JWT) per OpenID4VP v1.0
  - Validates VA-JWT signature, claims, and expiration
  - Extracts `cnf.jwk` for proof-of-possession validation
  - Uses `verifier_attestation:` scheme prefix

### Response Modes

Per OpenID4VP v1.0 Section 6, the verifier supports:

- **`direct_post`**: VP token and optional presentation submission in form-encoded POST body
  - Validates `vp_token` parameter
  - Validates optional `presentation_submission` parameter
  - Validates `state` parameter for request/response correlation
- **`direct_post.jwt`**: Signed JWT response containing VP token, optionally encrypted as JWE
  - Extracts `response` parameter containing JWT or JWE
  - Decrypts JWE using verifier's private key when encrypted
  - Validates JWT signature when signed
  - Extracts `vp_token` from JWT payload
  - Validates `nonce` and `state` from JWT payload or encrypted response
  - Handles both spec-compliant (JWT string) and wallet-specific (payload object) decryption results
- **`dc_api`**: Digital Credentials API response format (HAIP profile)
  - Handles HAIP-specific response structures
  - Supports credential object formats
- **`dc_api.jwt`**: Digital Credentials API with JWT-encapsulated response (HAIP profile)
  - Decrypts JWE response using X.509 EC private key
  - Extracts VP token from encrypted payload
  - Handles both JWT string and payload object formats

### Credential Query Formats

The verifier supports multiple credential query formats:

#### Presentation Exchange (PEX)
- **Format**: DIF Presentation Exchange v2.0.0
- **Input descriptors**: Supports multiple input descriptors with format-specific requirements
- **Presentation submission**: Validates `presentation_submission` with descriptor mapping
  - Validates `descriptor_map` array structure
  - Validates descriptor IDs match `input_descriptors` from presentation definition
  - Validates format compatibility between request and submission
- **Format support**: `vc+sd-jwt`, `dc+sd-jwt`, `jwt_vc_json`, `jwt_vp`, `mso_mdoc`
- **Nested credentials**: Supports `path_nested` for nested credential extraction
- **JSONPath support**: Uses JSONPath for credential extraction from nested structures

#### Digital Credentials Query Language (DCQL)
- **Format**: DCQL query format per OpenID4VP v1.0
- **Credential selection**: Supports credential ID, format, and claim path specifications
- **Metadata filtering**: Supports `vct_values` and `doctype_value` for credential type filtering
- **Claim paths**: Supports nested claim path specifications (e.g., `["org.iso.18013.5.1", "family_name"]`)
  - Resolves nested claim paths using deep object traversal
  - Filters extracted claims based on DCQL query paths
  - Supports both array and dot-notation path formats

### Credential Formats

The verifier accepts and validates the following credential formats:

- **`dc+sd-jwt`** / **`vc+sd-jwt`**: Selective Disclosure JWT credentials
  - SD-JWT token parsing using `@sd-jwt/decode` library
  - Disclosure validation and claim extraction
  - Key-binding JWT (`kb-jwt`) verification
  - Nonce validation in key-binding JWT
  - Selective disclosure claim extraction with digest validation
- **`jwt_vc_json`**: Standard JWT Verifiable Credentials
  - JWT signature verification
  - VC structure validation
  - Claim extraction from `vc` claim
  - Support for nested VCs in `verifiableCredential` array
- **`mso_mdoc`**: ISO/IEC 18013-5:2021 mDL format
  - CBOR-encoded DeviceResponse parsing
  - COSE Sign1 signature verification
  - MSO (Mobile Security Object) validation
  - Device key binding verification
  - Selective disclosure support for mDL data elements
  - Document type validation (`docType` matching)
  - Session transcript generation for device key binding

### Nonce and State Management

Per OpenID4VP v1.0 Section 5.1:

- **Nonce generation**: Cryptographically random nonce for replay attack prevention
- **Nonce validation**: Validates nonce in VP token or key-binding JWT
  - Supports nonce in key-binding JWT payload for SD-JWT credentials
  - Supports nonce in response JWT payload for `direct_post.jwt` mode
  - Supports nonce in encrypted response payload
  - Validates nonce matches session-stored nonce
- **State parameter**: Session state tracking for request/response correlation
  - Validates `state` parameter in VP response
  - Supports `state` in encrypted response payloads
  - State mismatch detection with detailed error messages
- **Session management**: Redis-based session storage with expiration
  - Stores presentation definition, DCQL query, nonce, state, and response mode
  - Tracks session status (pending, success, failed)
  - Stores extracted claims and verification results

### Wallet Metadata Discovery

Per OpenID4VP v1.0 Section 4.1:

- **Wallet metadata**: Supports `wallet_metadata` parameter in request URI POST requests
- **JWKS discovery**: Extracts wallet public keys from `wallet_metadata.jwks` for response encryption
- **Encryption preferences**: Uses wallet's `authorization_encryption_alg_values_supported` and `authorization_encryption_enc_values_supported`
- **Metadata validation**: Validates wallet metadata structure and required fields

### Response Encryption

For `direct_post.jwt` and `dc_api.jwt` response modes:

- **JWE encryption**: Decrypts JWT responses using verifier's private key
- **Encryption algorithms**: Supports `ECDH-ES+A256KW` (key wrapping) and `A256GCM` (content encryption)
- **Key selection**: Automatically selects decryption key based on JWE header
- **Decryption handling**: Handles both spec-compliant (JWT string) and wallet-specific (payload object) decryption results
- **Fallback support**: Gracefully handles different wallet encryption implementations

### Transaction Data

Per OpenID4VP v1.0 Section 5.1.2:

- **Transaction data support**: Optional `transaction_data` parameter in authorization requests
- **Transaction types**: Supports various transaction data types (e.g., `payment_data`, `qes_authorization`)
- **Transaction hashes**: Validates transaction data hashes when provided
- **Payment flows**: Special handling for payment transaction data
- **Base64URL encoding**: Supports base64url-encoded transaction data in requests

### Verifier Attestation

Per OpenID4VP v1.0 Section 7.3:

- **VA-JWT support**: Verifier Attestation JWT in JOSE header (`jwt` claim)
- **Proof-of-possession**: VA-JWT includes `cnf.jwk` for proof-of-possession
- **Attestation validation**: Validates VA-JWT signature, claims, and expiration
- **Client identification**: Uses `verifier_attestation:` scheme prefix
- **Self-signed VA-JWT**: Supports test/development self-signed VA-JWT generation (not for production)

### Claim Extraction and Validation

- **Selective disclosure**: Extracts disclosed claims from SD-JWT credentials
  - Validates disclosure digests
  - Extracts claims from disclosures using `@sd-jwt/decode` library
- **Claim path resolution**: Resolves nested claim paths for DCQL queries
  - Deep object traversal for nested paths
  - Supports array and dot-notation path formats
- **Format-specific extraction**: Handles different claim structures per credential format
  - SD-JWT: Extracts from disclosures
  - JWT VC: Extracts from `vc` claim or payload
  - mDL: Extracts from MSO data elements
- **Validation**: Validates extracted claims match requested claims from presentation definition or DCQL query
  - Compares extracted claims against requested input descriptors
  - Validates DCQL claim paths match extracted claims
  - Provides detailed error messages for claim mismatches

### Key-Binding JWT Verification

Per OpenID4VP v1.0 Section 7.2.2:

- **Key-binding JWT extraction**: Extracts `kb-jwt` from SD-JWT token (last segment after `~`)
- **Nonce validation**: Validates nonce in key-binding JWT payload matches session nonce
- **Signature verification**: Verifies key-binding JWT signature using wallet's public key
- **Audience validation**: Validates `aud` claim matches verifier's `client_id` or `response_uri`
- **Issuer validation**: Validates `iss` claim (typically `did:jwk:`)
- **Format detection**: Automatically detects key-binding JWT presence in SD-JWT tokens

### Standardized VP Endpoint

- **`GET /vp/request`**: Unified endpoint supporting various client identification schemes and query formats
  - `client_id_scheme`: `x509`, `did:web`, `did:jwk`
  - `profile`: `dcql`, `tx`, `mdl`
  - `credential_profile`: `pid`, `mdl`
  - `request_uri_method`: `get`, `post`
  - `response_mode`: `direct_post`, `direct_post.jwt`
  - `tx_data`: `true`, `false`

### Session Management

- **Redis-backed storage**: Stores VP sessions with state, nonce, presentation definition, and DCQL query
- **Status tracking**: Tracks session status (pending, success, failed)
- **Error storage**: Stores detailed error messages and validation failures
- **Claim storage**: Stores extracted claims after successful verification
- **Metadata storage**: Stores mDL metadata and verification details for debugging

## Wallet Client Capabilities

The `wallet-client/` directory contains a VCI + VP **test wallet** implementation that supports both credential issuance (VCI) and presentation (VP) flows per the respective specifications. This wallet is designed to exercise all issuer and verifier scenarios defined in this project.

### Wallet Client Architecture

The wallet client is a **wallet-holder** implementation that exercises both VCI (issuance) and VP (presentation) flows:

- **CLI** (`wallet-client/src/index.js`):
  - Non-interactive helper to obtain credentials via pre-authorized code flow
  - Generates proof JWTs, handles `c_nonce` and deferred issuance
  - Writes issued credentials + key-binding material into Redis
- **HTTP service** (`wallet-client/src/server.js`):
  - **`POST /issue`**: VCI pre-authorized flow using `openid-credential-offer://` or `haip://` links
  - **`POST /issue-codeflow`**: VCI authorization code flow with dynamic VP support
  - **`POST /present`**: OpenID4VP presentation using `openid4vp://` deep links
  - **`POST /session`**: Orchestrated test session API for end-to-end flows
  - **`GET /health`**: Health check endpoint
  - **`GET /logs/:sessionId`**: Fetch detailed wallet logs for a session
  - **`GET /session-status/:sessionId`**: Poll session outcome and status
- **Redis cache** (`wallet-client/src/lib/cache.js`):
  - Stores credentials by `credential_configuration_id` with key binding material
  - Stores detailed session logs for inspection
  - Session data includes status, results, errors, and timestamps

### VCI (Credential Issuance) Capabilities

#### Pre-Authorized Code Flow
Per OID4VCI v1.0 Section 4.1.1:

- **Grant type**: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- **Transaction code handling**: Supports `tx_code` parameter when `user_pin_required` is true
- **Deep link support**: Handles both `openid-credential-offer://` and `haip://` URL schemes
- **Credential offer resolution**: Resolves credential offers from deep links or credential offer URIs
- **Authorization details**: Includes `authorization_details` in token request for credential selection
- **Metadata discovery**: Discovers issuer metadata from `.well-known/openid-credential-issuer`
- **Authorization server discovery**: Discovers authorization server metadata per RFC 8414 when separate from credential issuer

#### Authorization Code Flow
Per OID4VCI v1.0 Section 4.1.2:

- **Grant type**: `authorization_code`
- **PKCE support**: Full RFC 7636 PKCE with `S256` code challenge method
- **Push Authorization Request (PAR)**: Supports RFC 9126 PAR when issuer advertises `pushed_authorization_request_endpoint`
- **Authorization endpoint**: Handles OAuth 2.0 authorization endpoint with `response_type=code`
- **Dynamic credential requests**: Supports dynamic credential requests requiring Verifiable Presentations
- **Redirect handling**: Processes authorization redirects with authorization code extraction
- **Authorization server discovery**: Discovers separate authorization server metadata when `authorization_servers` array is present

#### Proof-of-Possession (PoP)
Per OID4VCI v1.0 Section 7.2:

- **Proof type**: `jwt` (JWT-based proof)
- **Proof format**: Uses `proofs` (plural) format per V1.0 specification
- **Proof signing algorithms**: Supports `ES256`, `ES384`, `ES512`, `EdDSA` with algorithm negotiation
- **Public key embedding**: Embeds JWK in proof JWT header (`jwk` claim)
- **DID-based issuer**: Uses `did:jwk:` as proof issuer (`iss` claim)
- **Nonce handling**: Includes `c_nonce` from issuer in proof JWT payload
- **Audience validation**: Sets proof audience to credential issuer identifier
- **Proof type header**: Uses `typ: "openid4vci-proof+jwt"` in proof JWT header

#### Demonstrating Proof-of-Possession (DPoP)
Per RFC 9449:

- **DPoP generation**: Generates DPoP proof JWT for token endpoint requests
- **HTTP method binding**: Includes `htm` (HTTP method) and `htu` (HTTP URI) in DPoP payload
- **URI normalization**: Normalizes token endpoint URI per RFC 9449 Section 4.2
- **Key binding**: Uses separate key pair for DPoP (different from proof-of-possession key)
- **Token type detection**: Handles `DPoP` token type in token response

#### Wallet Attestation
Per EUDI Wallet specifications (TS3):

- **Wallet Instance Attestation (WIA)**: Generates WIA JWT for token endpoint and PAR requests
  - Includes `iss`, `aud`, `iat`, `exp`, `jti` claims
  - JWK in header for key resolution
  - TTL limited to 24 hours (default: 1 hour)
- **Wallet Unit Attestation (WUA)**: Generates WUA JWT for credential endpoint requests
  - Includes `eudi_wallet_info` with general info and key storage info
  - Includes `attested_keys` array with attested public keys
  - Optional `status` claim for revocation information
  - TTL up to 24 hours
- **Key attestation embedding**: Embeds WUA in proof JWT header as `key_attestation` claim per spec

#### Credential Request
Per OID4VCI v1.0 Section 7.1:

- **Credential identifier**: Uses `credential_configuration_id` in credential request
- **Proof format**: Uses `proofs` (plural) object with `jwt` array
- **Access token**: Includes Bearer token in Authorization header
- **Algorithm negotiation**: Selects proof signing algorithm based on issuer's `proof_signing_alg_values_supported`
- **Credential format detection**: Determines format from issuer metadata or credential response

#### Deferred Issuance
Per OID4VCI v1.0 Section 9.2:

- **Transaction ID handling**: Extracts `transaction_id` from `202 Accepted` response
- **Polling mechanism**: Polls deferred credential endpoint with configurable interval and timeout
- **Polling interval**: Configurable polling interval (default: 2 seconds)
- **Polling timeout**: Configurable timeout (default: 30 seconds)
- **Status tracking**: Tracks deferred issuance status until credential is ready

#### Credential Storage
- **Redis-backed storage**: Stores credentials by `credential_configuration_id`
- **Key binding material**: Stores private JWK, public JWK, and `did:jwk` identifier with each credential
- **Metadata storage**: Stores credential metadata including `c_nonce`, expiration, and issuer identifier
- **TTL management**: Configurable TTL for credential storage (default: 86400 seconds)

### VP (Verifiable Presentation) Capabilities

#### Authorization Request Processing
Per OpenID4VP v1.0 Section 5:

- **Deep link parsing**: Parses `openid4vp://` deep links with `request_uri` and `client_id` parameters
- **Request URI resolution**: Supports both `GET` and `POST` methods for request URI resolution
- **JWT authorization request**: Decodes and validates JWT-secured authorization requests (JAR)
- **Request by reference**: Fetches authorization request JWT from `request_uri`
- **Request by value**: Handles inline authorization request JWT in deep link

#### Response Mode Support
Per OpenID4VP v1.0 Section 6:

- **`direct_post`**: Sends `vp_token` and optional `presentation_submission` in form-encoded POST body
- **`direct_post.jwt`**: 
  - Builds signed JWT response containing VP token
  - Encrypts to JWE when verifier provides JWKS in `client_metadata`
  - Uses wallet's encryption preferences from `authorization_encryption_alg_values_supported` and `authorization_encryption_enc_values_supported`
  - Includes `iss`, `aud`, `iat`, `exp`, `nonce`, `state` claims in response JWT
- **`dc_api`** / **`dc_api.jwt`**: Supports Digital Credentials API response formats (HAIP profile)

#### Credential Query Formats

- **Presentation Exchange (PEX)**: 
  - Processes `presentation_definition` from authorization request
  - Builds `presentation_submission` with descriptor mapping
  - Validates input descriptors against presented credentials
- **Digital Credentials Query Language (DCQL)**:
  - Processes `dcql_query` from authorization request
  - Extracts requested claims using nested claim paths
  - Supports credential ID, format, and metadata filtering

#### Key-Binding JWT Generation
Per OpenID4VP v1.0 Section 7.2.2:

- **Key-binding JWT**: Generates `openid4vp-proof+jwt` for SD-JWT credentials
- **Nonce binding**: Includes verifier's `nonce` in key-binding JWT payload
- **Audience**: Sets audience to verifier's `client_id` or `response_uri`
- **Issuer**: Uses `did:jwk:` as key-binding JWT issuer
- **SD-JWT attachment**: Appends key-binding JWT as `kb-jwt` segment to SD-JWT token

#### Credential Format Handling

- **SD-JWT / DC+SD-JWT**:
  - Extracts SD-JWT token from various issuer response envelopes
  - Attaches key-binding JWT to SD-JWT token
  - Handles selective disclosure disclosures
- **JWT VC**:
  - Uses JWT VC tokens as-is for presentation
  - Supports `jwt_vc_json` format in presentation submission
- **mso_mdoc / mDL**:
  - Detects mDL credentials from stored format
  - Constructs proper `DeviceResponse` structure per ISO/IEC 18013-5:2021
  - Wraps `IssuerSigned` in `DeviceResponse` with `version`, `documents`, and `status`
  - CBOR-encodes DeviceResponse for presentation
  - Sets `format: "mso_mdoc"` in presentation submission

#### Credential Selection

- **Type-based selection**: Selects credential by `credential_configuration_id` or credential type
- **Automatic inference**: Infers credential type from presentation definition or DCQL query when not specified
- **Credential listing**: Lists available credential types from wallet storage
- **Format detection**: Automatically detects credential format (SD-JWT, JWT VC, mDL) from stored credential

#### Wallet Metadata

- **Metadata provision**: Optionally provides `wallet_metadata` in request URI POST requests
- **JWKS publication**: Can provide wallet public keys via `wallet_metadata.jwks` for response encryption
- **Encryption preferences**: Advertises supported encryption algorithms and methods

## Using the Wallet Client

The wallet client can be used in two modes:

#### CLI Mode (Quick Start)

For a simple pre-authorized SD-JWT issuance:

```bash
# in another terminal
cd wallet-client
npm install

# Example: use a pre-authorized offer from the issuer
node src/index.js --issuer http://localhost:3000 --fetch-offer /offer-no-code --credential VerifiablePortableDocumentA2SDJWT
```

**CLI Options:**
```bash
node src/index.js [--issuer URL] [--offer OFFER_URI] [--fetch-offer PATH] [--credential ID] [--key PATH]
```

- **--issuer**: Base URL of issuer (default: `http://localhost:3000`)
- **--offer**: Deep link `openid-credential-offer://?...` from issuer
- **--fetch-offer**: Issuer path to fetch an offer
- **--credential**: Desired `credential_configuration_id` (defaults to first in offer)
- **--key**: Optional path to an EC P-256 private JWK. If omitted, a new key is generated in-memory.

**What the CLI does:**
- Resolves the credential offer URI and downloads the offer JSON
- For **pre-authorized flow**:
  - Exchanges the pre-authorized code at token endpoint to get `access_token`
  - If `user_pin_required` is true, prompts for transaction code (PIN)
- Requests a fresh `c_nonce` at nonce endpoint
- Builds a proof JWT (`ES256`, `jwk` in header, `iss` = did:jwk, `aud` = issuer base URL, `nonce` = `c_nonce`)
- Calls credential endpoint with `credential_configuration_id` and the proof (using V1.0 `proofs` format)
- If issuer responds `202` with `transaction_id`, polls deferred credential endpoint until credential is ready
- Stores issued credential and key binding material in Redis for later use in presentations

#### Server Mode (Full Wallet Flows)

Start the wallet service:

```bash
cd wallet-client
npm install
npm start
```

Once running (default `http://localhost:4000`), you can:

- **Drive issuance**:
  - **`POST /issue`** for pre-authorized flows
  - **`POST /issue-codeflow`** for authorization code flows
- **Drive presentation**:
  - **`POST /present`** for OpenID4VP requests
- **Use orchestrated sessions for tests**:
  - **`POST /session`** to run end-to-end VCI or VP flows
  - **`GET /session-status/:sessionId`** to poll session outcome
  - **`GET /logs/:sessionId`** to fetch detailed wallet logs

This makes `wallet-client` a **comprehensive test wallet** that exercises all issuer and verifier scenarios defined in the rest of the project (credential formats, flows, response modes, client_id_schemes, and attestation mechanisms), while remaining clearly non-production and focused on conformance experimentation.

## References

- **OID4VCI**: [OpenID for Verifiable Credential Issuance v1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- **OpenID4VP**: [OpenID for Verifiable Presentations v1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **RFC 9101**: [JWT Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
- **RFC 9126**: [Push Authorization Request (PAR)](https://www.rfc-editor.org/rfc/rfc9126.html)
- **RFC 9449**: [Demonstrating Proof-of-Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
- **RFC 7636**: [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636.html)
- **EUDI Wallet ARF**: [Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases)
- **ISO/IEC 18013-5:2021**: [Mobile driving licence (mDL)](https://www.iso.org/standard/69084.html)


