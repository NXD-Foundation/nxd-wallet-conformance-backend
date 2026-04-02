import fs from "fs";
import path from "path";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import zlib from "zlib";
import base64url from "base64url";
import * as jose from "jose";
import { didKeyToJwks } from "../utils/cryptoUtils.js";
import { computeDidJwkIssuerDidAndKidFromDidKeys, loadDidIssuerPems } from "../utils/issuerDidKeys.js";
import {
  certToBase64,
  computeDidJwkFromPublic,
  computeDidWebFromServer,
  signStatusListToken,
  statusesToCompressedBuffer,
} from "../utils/statusListSigning.js";
import {
  statusListCreate,
  statusListGet,
  statusListGetAllIds,
  statusListDelete,
  statusListUpdateIndex,
} from "../services/cacheServiceRedis.js";

const serverURL = process.env.SERVER_URL || "http://localhost:3000";
const issuerSignatureType = process.env.ISSUER_SIGNATURE_TYPE || "did:web"; // one of: did:web | did:jwk | x509

// Load private key(s) for signing status list tokens
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
let certificatePemX509 = null;
let privateKeyPemX509 = null;
let privateKeyPemDidWeb = null;
try {
  certificatePemX509 = fs.readFileSync("./x509EC/client_certificate.crt", "utf8");
  privateKeyPemX509 = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
} catch (e) {
  // optional, only required in x509 mode
}
try {
  // DID:web private key to align with did:web DID document served by didweb routes
  privateKeyPemDidWeb = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
} catch (e) {
  // optional, used when did:web is active and separate key material is provided
}

/**
 * Status List Token Manager
 * Manages the creation, storage, and retrieval of status list tokens
 */
class StatusListManager {
  constructor() {
    // In-memory cache for tokens only; source of truth is Redis
    this.statusListTokens = new Map();
  }

  async initialize() {
    // Ensure at least one default list exists
    const ids = await statusListGetAllIds();
    if (!ids || ids.length === 0) {
      await this.createStatusList(1000, 1);
    }
  }

  /**
   * Create a status list aligned with credential issuance configuration
   * This ensures the status list uses the same issuer and key as credentials
   * @param {number} size - Number of tokens in the status list
   * @param {number} bits - Bits per status (1, 2, 4, or 8)
   * @param {Object} extra - Additional metadata
   * @param {Object} sessionObject - Session object containing signature type info (optional)
   * @returns {Object} Status list object
   */
  async createAlignedStatusList(size = 1000, bits = 1, extra = {}, sessionObject = null) {
    if (![1, 2, 4, 8].includes(bits)) {
      throw new Error("Bits must be one of: 1, 2, 4, 8");
    }

    // Determine signature type, preferring stored signature_type on the list, then session, then env
    let effectiveSignatureType = extra.signature_type;
    if (!effectiveSignatureType) {
      if (sessionObject) {
        effectiveSignatureType = sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
          ? "x509"
          : sessionObject.signatureType;
      } else {
        effectiveSignatureType = process.env.ISSUER_SIGNATURE_TYPE || "did:web";
      }
    }

    // Determine issuer and key configuration based on current settings
    let alignedIss, alignedKid, alignedX5c;
    
    if (effectiveSignatureType === "x509" && certificatePemX509) {
      alignedIss = serverURL;
      alignedX5c = certToBase64(certificatePemX509);
    } else if (effectiveSignatureType === "did:jwk") {
      const { did, kid } = await computeDidJwkFromPublic();
      alignedIss = did;
      alignedKid = kid;
    } else {
      // Default did:web
      const { did, kid } = computeDidWebFromServer();
      alignedIss = did;
      alignedKid = kid;
    }

    const id = uuidv4();
    const statusList = {
      id,
      size,
      bits,
      statuses: new Array(size).fill(0), // 0 = valid, 1 = revoked
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
      signature_type: effectiveSignatureType,
      iss: alignedIss,
      kid: alignedKid,
      x5c: alignedX5c,
      ...extra
    };

    await statusListCreate(id, statusList);
    return statusList;
  }

  /**
   * Create a new status list with specified size
   * @param {number} size - Number of tokens in the status list
   * @param {number} bits - Bits per status (1, 2, 4, or 8)
   * @returns {Object} Status list object
   */
  async createStatusList(size = 1000, bits = 1, extra = {}, signatureType = null) {
    if (![1, 2, 4, 8].includes(bits)) {
      throw new Error("Bits must be one of: 1, 2, 4, 8");
    }

    const id = uuidv4();
    const statusList = {
      id,
      size,
      bits,
      statuses: new Array(size).fill(0), // 0 = valid, 1 = revoked
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
      signature_type: signatureType || extra.signature_type || process.env.ISSUER_SIGNATURE_TYPE || "did:web",
      ...extra
    };

    await statusListCreate(id, statusList);
    return statusList;
  }

  /**
   * Get a status list by ID
   * @param {string} id - Status list ID
   * @returns {Object|null} Status list object or null if not found
   */
  async getStatusList(id) {
    return await statusListGet(id);
  }

  /**
   * Update the status of a token in the status list
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @param {number} status - Status value (0 = valid, 1 = revoked)
   * @returns {boolean} Success status
   */
  async updateTokenStatus(statusListId, index, status) {
    const ok = await statusListUpdateIndex(statusListId, index, status);
    if (ok) this.statusListTokens.delete(statusListId);
    return ok;
  }

  /**
   * Get the status of a token in the status list
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @returns {number|null} Status value or null if not found
   */
  async getTokenStatus(statusListId, index) {
    const statusList = await statusListGet(statusListId);
    if (!statusList || index < 0 || index >= statusList.size) return null;
    return statusList.statuses[index];
  }

  /**
   * Convert status array to compressed bit array
   * @param {Array} statuses - Array of status values
   * @param {number} bits - Bits per status
   * @returns {Buffer} Compressed buffer
   */
  statusesToCompressedBuffer(statuses, bits) {
    return statusesToCompressedBuffer(statuses, bits);
  }

  /**
   * Generate a Status List Token JWT
   * @param {string} statusListId - Status list ID
   * @param {Object} sessionObject - Session object containing signature type info (optional)
   * @returns {string} JWT token
   */
  async generateStatusListToken(statusListId, sessionObject = null) {
    const statusList = await statusListGet(statusListId);
    if (!statusList) throw new Error("Status list not found");

    // Check if we have a cached token and ensure it's not expired
    if (this.statusListTokens.has(statusListId)) {
      const cached = this.statusListTokens.get(statusListId);
      if (cached.updated_at >= statusList.updated_at) {
        try {
          const decodedCached = jwt.decode(cached.token);
          const nowEpoch = Math.floor(Date.now() / 1000);
          if (decodedCached && decodedCached.exp && decodedCached.exp > nowEpoch) {
            return cached.token;
          }
        } catch (e) {
          // fall through to regenerate on decode error
        }
      }
    }

    const token = await signStatusListToken(
      statusListId,
      statusList,
      sessionObject,
      serverURL
    );

    // Cache the token
    this.statusListTokens.set(statusListId, {
      token,
      updated_at: statusList.updated_at
    });

    return token;
  }

  /**
   * Verify a Status List Token
   * @param {string} token - JWT token
   * @param {Object} sessionObject - Session object containing signature type info (optional)
   * @returns {Object|null} Decoded payload or null if invalid
   */
  async verifyStatusListToken(token, sessionObject = null) {
    try {
      // Determine signature type using same logic as credential generation
      let effectiveSignatureType;
      if (sessionObject) {
        effectiveSignatureType = sessionObject.isHaip && process.env.ISSUER_SIGNATURE_TYPE === "x509"
          ? "x509"
          : sessionObject.signatureType;
      } else {
        effectiveSignatureType = process.env.ISSUER_SIGNATURE_TYPE || "did:web";
      }

      // Compute expected issuer aligned with generation
      let expectedIssuer;
      if (effectiveSignatureType === "x509") {
        expectedIssuer = serverURL;
      } else if (effectiveSignatureType === "did:jwk") {
        expectedIssuer = (await computeDidJwkFromPublic()).did;
      } else {
        expectedIssuer = computeDidWebFromServer().did;
      }
      let verifyKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
      if (effectiveSignatureType === "did:web" || effectiveSignatureType === "did:jwk") {
        try {
          verifyKeyPem = loadDidIssuerPems().publicPem;
        } catch {
          /* keep public-key.pem */
        }
      }
      const decoded = jwt.verify(token, verifyKeyPem, {
        algorithms: ["ES256"],
        issuer: expectedIssuer,
      });
      return decoded;
    } catch (error) {
      console.error("Status list token verification failed:", error);
      return null;
    }
  }

  async verifyStatusListTokenResolved(token) {
    try {
      const header = jose.decodeProtectedHeader(token);
      let keyLike = null;

      if (header && header.x5c && header.x5c.length > 0) {
        const certPem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----\n`;
        keyLike = await jose.importX509(certPem, header.alg || "ES256");
      } else if (header && header.kid && header.kid.startsWith("did:")) {
        const did = header.kid.split("#")[0];
        try {
          const jwks = await didKeyToJwks(did);
          if (!jwks) throw new Error("No JWKS from DID resolution");
          const jwk = jwks.keys.find((k) => k.kid === header.kid) || jwks.keys[0];
          if (!jwk) throw new Error("No matching JWK for kid");
          keyLike = await jose.importJWK(jwk, header.alg || "ES256");
        } catch (e) {
          // Local fallback: same SPKI as did:web DID document (didjwks/did_public.pem)
          let publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
          try {
            publicKeyPem = loadDidIssuerPems().publicPem;
          } catch {
            /* keep public-key.pem */
          }
          keyLike = await jose.importSPKI(publicKeyPem, header.alg || "ES256");
        }
      } else {
        // Fallback to local public key
        const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
        keyLike = await jose.importSPKI(publicKeyPem, header.alg || "ES256");
      }

      const { payload } = await jose.jwtVerify(token, keyLike, {
        algorithms: ["ES256", "ES384"],
      });
      return payload;
    } catch (error) {
      console.error("Status list token verification (resolved) failed:", error);
      return null;
    }
  }

  /**
   * Check if a token is revoked using a status list
   * @param {string} statusListToken - Status list JWT token
   * @param {number} tokenIndex - Index of the token to check
   * @returns {boolean} True if token is revoked, false if valid
   */
  async isTokenRevoked(statusListToken, tokenIndex) {
    try {
      const decoded = await this.verifyStatusListToken(statusListToken);
      if (!decoded || !decoded.status_list) {
        return false;
      }

      const { bits, lst } = decoded.status_list;
      
      // Decompress the status list
      const compressedBuffer = base64url.toBuffer(lst);
      const decompressedBuffer = zlib.inflateSync(compressedBuffer);
      
      // Convert to bits array
      const bitsArray = [];
      for (let i = 0; i < decompressedBuffer.length; i++) {
        const byte = decompressedBuffer[i];
        for (let bit = 0; bit < 8; bit++) {
          bitsArray.push((byte >> bit) & 1);
        }
      }

      // Calculate the bit index for the token
      const bitIndex = tokenIndex * bits;
      if (bitIndex >= bitsArray.length) {
        return false; // Index out of range, assume valid
      }

      // Extract the status value
      let status = 0;
      for (let i = 0; i < bits; i++) {
        if (bitIndex + i < bitsArray.length) {
          status |= bitsArray[bitIndex + i] << i;
        }
      }

      return status !== 0; // Non-zero means revoked
    } catch (error) {
      console.error("Error checking token revocation status:", error);
      return false;
    }
  }

  /**
   * Create a status reference for a credential
   * @param {string} statusListId - Status list ID
   * @param {number} index - Token index in the status list
   * @returns {Object} Status reference object
   */
  createStatusReference(statusListId, index) {
    return {
      status_list: {
        uri: `${serverURL}/status-list/${statusListId}`,
        idx: index
      }
    };
  }

  /**
   * Get all status lists (for admin purposes)
   * @returns {Array} Array of status list objects
   */
  async getAllStatusLists() {
    const ids = await statusListGetAllIds();
    const lists = [];
    for (const id of ids) {
      const sl = await statusListGet(id);
      if (sl) lists.push(sl);
    }
    return lists;
  }

  /**
   * Delete a status list
   * @param {string} id - Status list ID
   * @returns {boolean} Success status
   */
  async deleteStatusList(id) {
    const ok = await statusListDelete(id);
    if (ok) this.statusListTokens.delete(id);
    return ok;
  }
}

// Create a singleton instance
const statusListManager = new StatusListManager();
await statusListManager.initialize();

export default statusListManager;

// Export utility functions
export {
  StatusListManager
};
