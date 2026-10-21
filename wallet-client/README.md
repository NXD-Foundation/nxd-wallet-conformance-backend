
## DPoP nonce recovery

The wallet handles AS `400 use_dpop_nonce` errors and resource-server `401` DPoP nonce challenges, including empty-body errors. It retains successful-response nonce updates and regenerates proofs with the session's original binding key. AS and resource nonces are independent of credential `c_nonce`.

CS-04 uses independent WIA authentication and DPoP keys: WIA PoP uses WIA `cnf`, PAR `dpop_jkt` uses the DPoP key, and access-token `cnf.jkt` checks use the actual DPoP key. CS-05/BWIA issuer rules remain unchanged. See [PR #355 alignment](../docs/cs04-independent-dpop-keys.md).

WE BUILD's session WIA is retained across PAR, token exchange, handoff and retries; each request gets fresh PoP/DPoP proof material. Credential requests and deferred transaction bodies stay unchanged during nonce-only retries. Recovery is bounded to two nonce retries per logical request and five sends overall, retaining the existing attestation retry limit. Missing nonce headers or binding keys fail explicitly, and DPoP-bound access never downgrades to Bearer.

Callback configuration, presentation invocation and credential-nonce acquisition policies remain those of the WE BUILD profile. See [the port validation report](../docs/webuild-dpop-nonce-port.md) for source commits, pinned conformance documents, regression coverage and baseline failures.
