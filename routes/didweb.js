import express from "express";
import { convertPemToJwk } from "../utils/didjwks.js";

const didWebRouter = express.Router();
const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const proxyPath = process.env.PROXY_PATH || null;

// Helper function to build DID document
// References in authentication and assertionMethod MUST match verificationMethod.id exactly
// (full DID URL, e.g. did:web:itb.ilabs.ai:diipv5#keys-1) so resolvers can dereference correctly.
function buildDidDocument(controller, serviceURL, jwks) {
  const did = `did:web:${controller}`;
  const keyId = `${did}#keys-1`;
  return {
    "@context": "https://www.w3.org/ns/did/v1",
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: jwks,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    service: [
      {
        id: `${did}#jwks`,
        type: "JsonWebKey2020",
        serviceEndpoint: `${serviceURL}/.well-known/jwks.json`,
      },
    ],
  };
}

didWebRouter.get(["/.well-known/did.json","/did.json"], async (req, res) => {
  let jwks = await convertPemToJwk();
  let controller = serverURL;
  let serviceURL = serverURL;
  if (proxyPath) {
    controller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
    serviceURL = serverURL;
  }

  controller = controller.replace("https://","").replace("http://","");
  let didDoc = buildDidDocument(controller, serviceURL, jwks);

  res.json(didDoc);
});

// Handle path-based DIDs like /rfc-issuer/did.json for did:web:itb.ilabs.ai:rfc-issuer
// NOTE: All path-based DIDs (e.g., rfc-issuer, diipv5) currently use the same public key
// from ./didjwks/did_public.pem. The key IDs differ (did:web:itb.ilabs.ai:rfc-issuer#keys-1
// vs did:web:itb.ilabs.ai:diipv5#keys-1) because they include the DID identifier, but
// the actual key material is the same. This is intentional - all path-based DIDs represent
// different endpoints/deployments of the same issuer using shared key material.
// If separate keys are needed for different DIDs, this would require path-based key selection.
didWebRouter.get("/:path/did.json", async (req, res) => {
  let jwks = await convertPemToJwk();
  const pathSegment = req.params.path;

  let controller = serverURL;
  let serviceURL = serverURL;
  if (proxyPath) {
    controller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
    serviceURL = serverURL;
  }

  // Build controller with path segment: e.g., "itb.ilabs.ai:rfc-issuer"
  controller = controller.replace("https://","").replace("http://","");
  if (pathSegment) {
    controller = `${controller}:${pathSegment}`;
  }

  let didDoc = buildDidDocument(controller, serviceURL, jwks);

  res.json(didDoc);
});

didWebRouter.get(["/.well-known/jwks.json"], async (req, res) => {
  let controller = serverURL;
  if (proxyPath) {
    controller = serverURL.replace("/"+proxyPath,"") + ":" + proxyPath;
  }
  controller = controller.replace("https://","").replace("http://","");
  const did = `did:web:${controller}`;
  let jwks = await convertPemToJwk();
  let result = {
    keys: [{ ...jwks, use: "sig", kid: `${did}#keys-1` }],
  };

  res.json(result);
});

export default didWebRouter;
