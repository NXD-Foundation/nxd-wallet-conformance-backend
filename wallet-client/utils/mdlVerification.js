import { decode } from 'cbor-x';
import base64url from 'base64url';
import crypto from "node:crypto";
import { DeviceResponse, cborEncode, DataItem } from "@animo-id/mdoc";
import { mdocContext } from "./mdocContext.js";
import { normalizeDcqlClaimsToSegmentLists } from "../src/lib/dcqlClaimsPaths.js";

/**
 * Custom mDL verification using cbor-x decoder
 * This bypasses the buggy @auth0/mdl library and provides reliable verification
 * 
 * @param {string} vpTokenBase64 - Base64url encoded mDL token
 * @param {Object} options - Verification options
 * @param {string[]} options.requestedFields - Array of field names to extract (for selective disclosure)
 * @param {boolean} options.validateStructure - Whether to perform strict structure validation (default: true)
 * @param {boolean} options.includeMetadata - Whether to include metadata in response (default: true)
 * @returns {Object} Verification result
 */
export async function verifyReceivedMdlToken(vpTokenBase64, options = {}, documentType = "urn:eu.europa.ec.eudi:pid:1") {
  const {
    requestedFields = null,
    validateStructure = true,
    includeMetadata = true
  } = options;
  
  try {
    // Step 1: Decode base64url to buffer
    const buffer = base64url.toBuffer(vpTokenBase64);
    
    // Step 2: Decode CBOR structure
    const decodedData = decode(buffer);
    
    // Debug: Log the structure to understand what we received
    console.log("[mdl-verify] Decoded CBOR structure keys:", Object.keys(decodedData || {}));
    console.log("[mdl-verify] Decoded CBOR type:", typeof decodedData, Array.isArray(decodedData) ? "(array)" : "");
    if (decodedData && typeof decodedData === 'object' && !Array.isArray(decodedData)) {
      console.log("[mdl-verify] Top-level fields:", JSON.stringify(Object.keys(decodedData)));
    }
    
    // Step 3: Detect format - could be DeviceResponse (presentation) or Document (issuance)
    let deviceResponse;
    let document;
    
    if (decodedData.version && decodedData.documents && Array.isArray(decodedData.documents)) {
      // Full DeviceResponse format (used during presentation)
      console.log("[mdl-verify] Detected DeviceResponse format (presentation)");
      deviceResponse = decodedData;
      
      if (validateStructure && deviceResponse.documents.length === 0) {
        throw new Error("No documents found in mDL");
      }
      
      document = deviceResponse.documents[0];
    } else if (decodedData.docType || decodedData.issuerSigned) {
      // Single Document format (used during issuance)
      console.log("[mdl-verify] Detected single Document format (issuance)");
      document = decodedData;
      deviceResponse = {
        version: "1.0", // Default version for issued credentials
        documents: [document],
        status: 0
      };
    } else if (decodedData.nameSpaces && decodedData.issuerAuth) {
      // IssuerSigned format (minimal issuance format per ISO 18013-5)
      console.log("[mdl-verify] Detected IssuerSigned format (minimal issuance)");
      // Wrap IssuerSigned in a Document structure
      document = {
        docType: documentType || "org.iso.18013.5.1.mDL", // Use provided or default docType
        issuerSigned: decodedData,
        deviceSigned: null // Not present during issuance
      };
      deviceResponse = {
        version: "1.0",
        documents: [document],
        status: 0
      };
    } else {
      // Unknown format - might be wrapped or use non-standard field names
      console.log("[mdl-verify] Warning: Unknown format, attempting to unwrap/parse");
      
      // Try common envelope patterns
      let unwrapped = decodedData;
      
      // Check if it's wrapped in a 'credential' field
      if (decodedData.credential) {
        console.log("[mdl-verify] Found 'credential' wrapper, unwrapping...");
        unwrapped = decodedData.credential;
      }
      
      // Check if the unwrapped data is a string (might need another decode)
      if (typeof unwrapped === 'string') {
        console.log("[mdl-verify] Credential is a string, attempting to decode again...");
        try {
          const innerBuffer = base64url.toBuffer(unwrapped);
          unwrapped = decode(innerBuffer);
          console.log("[mdl-verify] Successfully decoded inner credential");
        } catch (e) {
          console.warn("[mdl-verify] Could not decode inner string:", e.message);
        }
      }
      
      // Re-check format after unwrapping
      if (unwrapped.version && unwrapped.documents && Array.isArray(unwrapped.documents)) {
        console.log("[mdl-verify] After unwrapping: Detected DeviceResponse format");
        deviceResponse = unwrapped;
        document = deviceResponse.documents[0];
      } else if (unwrapped.docType || unwrapped.issuerSigned) {
        console.log("[mdl-verify] After unwrapping: Detected Document format");
        document = unwrapped;
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      } else if (unwrapped.nameSpaces && unwrapped.issuerAuth) {
        console.log("[mdl-verify] After unwrapping: Detected IssuerSigned format");
        document = {
          docType: documentType || "org.iso.18013.5.1.mDL",
          issuerSigned: unwrapped,
          deviceSigned: null
        };
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      } else {
        // Still unknown after unwrapping
        console.log("[mdl-verify] Still unknown format after unwrapping. Keys:", Object.keys(unwrapped || {}));
        if (validateStructure) {
          throw new Error("Invalid mDL structure: not a DeviceResponse or Document");
        }
        // Last resort: treat as document
        document = unwrapped;
        deviceResponse = { version: "1.0", documents: [document], status: 0 };
      }
    }
    
    if (validateStructure && !document.docType) {
      console.warn("[mdl-verify] Warning: Document missing docType, using default");
      document.docType = documentType || "org.iso.18013.5.1.mDL";
    }
    
    // Step 5: Extract claims from issuerSigned nameSpaces
    const allClaims = {};
    if (document.issuerSigned?.nameSpaces) {
      // Try multiple possible namespace identifiers
      // 1. Use the provided documentType
      // 2. Use the standard ISO namespace "org.iso.18013.5.1"
      // 3. Use the EU namespace "urn:eu.europa.ec.eudi:pid:1"
      // 4. Try any available namespace
      let isoNamespace = document.issuerSigned.nameSpaces[documentType];
      
      if (!isoNamespace && documentType === "org.iso.18013.5.1.mDL") {
        // For mDL docType, try the standard ISO namespace
        isoNamespace = document.issuerSigned.nameSpaces["org.iso.18013.5.1"];
      }
      
    
      
      if (!isoNamespace) {
        // Fallback: try the first available namespace
        const availableNamespaces = Object.keys(document.issuerSigned.nameSpaces);
        if (availableNamespaces.length > 0) {
          isoNamespace = document.issuerSigned.nameSpaces[availableNamespaces[0]];
          console.log("Using fallback namespace:", availableNamespaces[0]);
        }
      }
      
      if (isoNamespace && Array.isArray(isoNamespace)) {
        isoNamespace.forEach(element => {
          try {
            // Handle CBOR tags properly - elements are wrapped in CBOR tags
            let elementDecoded;
            if (element?.tag !== undefined) {
              elementDecoded = decode(element.value);
            } else {
              elementDecoded = decode(element);
            }
            
            if (elementDecoded?.elementIdentifier && elementDecoded.elementValue !== undefined) {
              allClaims[elementDecoded.elementIdentifier] = elementDecoded.elementValue;
            }
          } catch (e) {
            // Skip elements that can't be decoded - this is normal for some CBOR structures
          }
        });
      }
    }
    
    // Step 6: Apply field filtering if requested (for selective disclosure)
    let claims = allClaims;
    // if (requestedFields && Array.isArray(requestedFields)) {
    //   claims = {};
    //   requestedFields.forEach(field => {
    //     if (allClaims[field] !== undefined) {
    //       claims[field] = allClaims[field];
    //     }
    //   });
    // }
    
    // Step 7: Build result object
    const result = {
      success: true,
      docType: document.docType,
      version: deviceResponse.version,
      status: deviceResponse.status,
      claims: claims
    };
    
    // Add metadata if requested
    if (includeMetadata) {
      result.metadata = {
        totalFields: Object.keys(allClaims).length,
        extractedFields: Object.keys(claims).length,
        requestedFields: requestedFields,
        hasDeviceSigned: !!document.deviceSigned,
        hasIssuerSigned: !!document.issuerSigned,
        extractedAt: new Date().toISOString()
      };
    }
    
    return result;
    
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    };
  }
}

/**
 * Validates if extracted claims match the requested fields from presentation definition
 * This replaces the hasOnlyAllowedFields function for mDL verification
 * 
 * @param {Object} extractedClaims - Claims extracted from mDL
 * @param {string[]} requestedFields - Fields that were requested in presentation definition (JSONPath format)
 * @returns {boolean} True if claims match requested fields
 */
export function validateMdlClaims(extractedClaims, requestedFields) {
  if (!requestedFields || !Array.isArray(requestedFields)) {
    return true; // No specific fields requested
  }
  
  // Extract field names from JSONPath expressions
  // JSONPath format: "$['org.iso.18013.5.1']['field_name']"
  const fieldNames = requestedFields.map(jsonPath => {
    // Extract the field name from the JSONPath
    const match = jsonPath.match(/\['([^']+)'\]$/);
    return match ? match[1] : null;
  }).filter(fieldName => fieldName !== null);
  
  // Check if all requested fields are present
  const missingFields = fieldNames.filter(fieldName => extractedClaims[fieldName] === undefined);
  
  
  if (missingFields.length > 0) {
    console.warn(`Missing requested fields: ${missingFields.join(', ')}`);
    console.log('extractedClaims', extractedClaims);
    console.log('fieldNames', fieldNames);
    return false;
  }
  
  return true;
}

/**
 * RFC002 SessionTranscript for OpenID4VP mdoc (OID4VPHandover), CBOR-encoded for DeviceAuthentication.
 * Shape: [null, null, ["OID4VPHandover", client_id, response_uri, mdoc_generated_nonce, verifier_nonce]]
 *
 * @param {{ client_id: string, response_uri: string, nonce: string }} oid4vpData
 * @param {string} mdocGeneratedNonce
 * @returns {Uint8Array}
 */
/**
 * ISO mDL docType uses issuer namespace `org.iso.18013.5.1`; EU PID docType matches its namespace URI.
 * @param {string} docType
 * @returns {string}
 */
export function defaultMdocNamespaceForDocType(docType) {
  if (docType === "org.iso.18013.5.1.mDL") return "org.iso.18013.5.1";
  return docType;
}

/**
 * Map DCQL path segments to a Presentation Exchange JSONPath understood by @animo-id/mdoc
 * (`$['namespace']['elementIdentifier']`).
 * @param {string[]} segments
 * @param {string} docType
 */
export function dcqlSegmentsToMdocPexPath(segments, docType) {
  if (!segments?.length) return null;
  let nameSpace;
  let elementIdentifier;
  if (segments.length === 1) {
    nameSpace = defaultMdocNamespaceForDocType(docType);
    elementIdentifier = segments[0];
  } else {
    nameSpace = segments[0];
    elementIdentifier = segments[segments.length - 1];
  }
  return `$['${nameSpace}']['${elementIdentifier}']`;
}

/**
 * Build a Presentation Definition so DeviceResponse.sign() runs ISO 18013-5 selective disclosure
 * (digest-only device nameSpaces) for DCQL `credentials[].claims`.
 *
 * @param {string} docType — must equal input_descriptor.id for @animo-id/mdoc matching
 * @param {{ claims?: unknown } | null | undefined} dcqlEntry
 * @returns {object | null}
 */
export function presentationDefinitionFromDcqlMdocClaims(docType, dcqlEntry) {
  const segmentLists = normalizeDcqlClaimsToSegmentLists(dcqlEntry?.claims);
  if (segmentLists.length === 0) return null;
  const fields = [];
  for (const segs of segmentLists) {
    const p = dcqlSegmentsToMdocPexPath(segs, docType);
    if (p) fields.push({ path: [p], intent_to_retain: false });
  }
  if (fields.length === 0) return null;
  return {
    id: `dcql-mdoc-${docType}`,
    input_descriptors: [
      {
        id: docType,
        format: { mso_mdoc: { alg: ["ES256", "ES384"] } },
        constraints: {
          limit_disclosure: "required",
          fields,
        },
      },
    ],
  };
}

export function getSessionTranscriptBytes(oid4vpData, mdocGeneratedNonce) {
  const { client_id: clientId, response_uri: responseUri, nonce: verifierNonce } =
    oid4vpData;
  return cborEncode(
    DataItem.fromData([
      null,
      null,
      ["OID4VPHandover", clientId, responseUri, mdocGeneratedNonce, verifierNonce],
    ]),
  );
}

/**
 * Extract device nonce from mDL device response (if present)
 * This would typically be used for session transcript construction
 * 
 * @param {string} vpTokenBase64 - Base64url encoded mDL token
 * @returns {string|null} Device nonce if found, null otherwise
 */
export async function extractDeviceNonce(vpTokenBase64) {
  try {
    const buffer = base64url.toBuffer(vpTokenBase64);
    const deviceResponse = decode(buffer);
    
    // Look for device nonce in deviceSigned section
    if (deviceResponse.documents?.[0]?.deviceSigned) {
      const deviceSigned = deviceResponse.documents[0].deviceSigned;
      
      // The exact location of the device nonce may vary depending on the implementation
      // This is a simplified extraction - real implementation may need more sophisticated parsing
      if (deviceSigned.deviceAuth) {
        // Device nonce might be embedded in deviceAuth structure
        // This would need to be adapted based on the actual mDL implementation
        return null; // Placeholder for now
      }
    }
    
    return null;
  } catch (error) {
    console.warn("Could not extract device nonce:", error.message);
    return null;
  }
}

/**
 * Constructs a DeviceResponse for presentation from stored credential
 * This is used when the wallet presents an mdoc credential to a verifier
 * 
 * @param {string|Object} storedCredential - The stored credential (could be IssuerSigned, Document, or DeviceResponse)
 * @param {Object} options - Presentation options
 * @param {string} options.docType - Document type (e.g., "org.iso.18013.5.1.mDL")
 * @param {Object} options.sessionTranscript - Optional session transcript for deviceAuth
 * @returns {Promise<{ vpToken: string, mdocGeneratedNonce: string | null }>}
 */
export async function buildMdocPresentation(storedCredential, options = {}) {
  const { encode: encodeCbor } = await import('cbor-x');
  const {
    docType = "org.iso.18013.5.1.mDL",
    clientId,
    responseUri,
    verifierGeneratedNonce,
    devicePrivateJwk,
    presentationDefinition,
    dcqlEntry,
    mdocGeneratedNonceOverride,
  } = options;
  
  console.log("[mdoc-present] Building DeviceResponse for presentation");
  console.log("[mdoc-present] Stored credential type:", typeof storedCredential);
  
  let issuerSigned;
  let effectiveDocType = docType;
  
  // Determine what format we have stored
  if (typeof storedCredential === 'string') {
    // Stored as base64url encoded CBOR - decode it first
    console.log("[mdoc-present] Decoding stored base64url credential");
    const buffer = base64url.toBuffer(storedCredential);
    const decoded = decode(buffer);
    
    if (decoded.version && decoded.documents) {
      const firstDocument = Array.isArray(decoded.documents)
        ? decoded.documents[0]
        : null;
      if (!firstDocument?.issuerSigned) {
        throw new Error("Stored mdoc DeviceResponse does not contain issuerSigned data");
      }
      effectiveDocType = firstDocument.docType || effectiveDocType;
      issuerSigned = firstDocument.issuerSigned;
    } else if (decoded.docType || decoded.issuerSigned) {
      // Document format
      effectiveDocType = decoded.docType || effectiveDocType;
      issuerSigned = decoded.issuerSigned || decoded;
    } else if (decoded.nameSpaces && decoded.issuerAuth) {
      // IssuerSigned format
      issuerSigned = decoded;
    } else {
      throw new Error("Unknown mdoc credential format");
    }
  } else if (typeof storedCredential === 'object') {
    // Stored as object
    if (storedCredential.version && storedCredential.documents) {
      const firstDocument =
        Array.isArray(storedCredential.documents) &&
        storedCredential.documents.length > 0
          ? storedCredential.documents[0]
          : null;
      if (!firstDocument?.issuerSigned) {
        throw new Error("Stored mdoc DeviceResponse object does not contain issuerSigned data");
      }
      effectiveDocType = firstDocument.docType || effectiveDocType;
      issuerSigned = firstDocument.issuerSigned;
    } else if (storedCredential.docType || storedCredential.issuerSigned) {
      // Document format
      effectiveDocType = storedCredential.docType || effectiveDocType;
      issuerSigned = storedCredential.issuerSigned || storedCredential;
    } else if (storedCredential.nameSpaces && storedCredential.issuerAuth) {
      // IssuerSigned format
      issuerSigned = storedCredential;
    } else {
      throw new Error("Unknown mdoc credential format");
    }
  } else {
    throw new Error("Invalid stored credential type");
  }
  
  if (!clientId || !responseUri || !verifierGeneratedNonce || !devicePrivateJwk) {
    throw new Error(
      "Missing required OpenID4VP mdoc presentation inputs: clientId, responseUri, verifierGeneratedNonce, and devicePrivateJwk are required",
    );
  }

  const issuerSignedMdoc = encodeCbor({
    version: "1.0",
    documents: [
      {
        docType: effectiveDocType,
        issuerSigned,
      },
    ],
    status: 0,
  });

  const mdocGeneratedNonce =
    typeof mdocGeneratedNonceOverride === "string" &&
    mdocGeneratedNonceOverride.length > 0
      ? mdocGeneratedNonceOverride
      : crypto.randomBytes(16).toString("base64url");
  const sessionTranscriptBytes = getSessionTranscriptBytes(
    {
      client_id: clientId,
      response_uri: responseUri,
      nonce: verifierGeneratedNonce,
    },
    mdocGeneratedNonce,
  );
  let builder = DeviceResponse.from(new Uint8Array(issuerSignedMdoc)).usingSessionTranscriptBytes(
    sessionTranscriptBytes,
  );

  const dcqlPd = presentationDefinitionFromDcqlMdocClaims(
    effectiveDocType,
    dcqlEntry,
  );
  const pdForSigning = dcqlPd ?? presentationDefinition;
  if (!pdForSigning) {
    throw new Error(
      "mdoc presentation requires presentation_definition and/or dcql_query.credentials[].claims with at least one path",
    );
  }
  builder = builder.usingPresentationDefinition(pdForSigning);

  const signedResponse = await builder
    .authenticateWithSignature(devicePrivateJwk, "ES256")
    .sign(mdocContext);

  console.log("[mdoc-present] Constructed DeviceResponse with docType:", effectiveDocType);

  const base64urlEncoded = base64url.encode(Buffer.from(signedResponse.encode()));

  console.log("[mdoc-present] Encoded DeviceResponse length:", base64urlEncoded.length);

  return { vpToken: base64urlEncoded, mdocGeneratedNonce };
}

/**
 * Checks if a credential is an mdoc/mDL credential
 * 
 * @param {string|Object} credential - The credential to check
 * @returns {boolean} True if it's an mdoc credential
 */
export function isMdocCredential(credential) {
  try {
    if (typeof credential === 'string') {
      // Check if it's base64url encoded CBOR
      // SD-JWT has '~', JWT has 3 parts with '.'
      if (credential.includes('~')) return false; // SD-JWT
      if (credential.split('.').length === 3) return false; // JWT
      
      // Try to decode as CBOR
      const buffer = base64url.toBuffer(credential);
      const decoded = decode(buffer);
      
      // Check for mdoc structures
      if (decoded.version && decoded.documents) return true; // DeviceResponse
      if (decoded.docType || decoded.issuerSigned) return true; // Document
      if (decoded.nameSpaces && decoded.issuerAuth) return true; // IssuerSigned
      
      return false;
    } else if (typeof credential === 'object' && credential !== null) {
      // Check object structure
      if (credential.version && credential.documents) return true; // DeviceResponse
      if (credential.docType || credential.issuerSigned) return true; // Document
      if (credential.nameSpaces && credential.issuerAuth) return true; // IssuerSigned
      
      return false;
    }
    
    return false;
  } catch (e) {
    // If decoding fails, it's probably not an mdoc
    return false;
  }
}

export default {
  verifyMdlToken: verifyReceivedMdlToken,
  validateMdlClaims,
  getSessionTranscriptBytes,
  extractDeviceNonce,
  buildMdocPresentation,
  isMdocCredential
}; 
