import { p256 } from "@noble/curves/p256";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { hkdf } from "@panva/hkdf";
import * as x509 from "@peculiar/x509";
import { X509Certificate } from "@peculiar/x509";
import { exportJWK, importX509 } from "jose";
import * as mdoc from "@animo-id/mdoc";

const { CoseKey, KeyOps, KeyType, MacAlgorithm, hex, stringToBytes } = mdoc;

function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  return Uint8Array.from(value);
}

export const mdocContext = {
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes);
      return new Uint8Array(digest);
    },
    random: (length) => crypto.getRandomValues(new Uint8Array(length)),
    calculateEphemeralMacKeyJwk: async (input) => {
      const { privateKey, publicKey, sessionTranscriptBytes, info } = input;
      const ikm = p256
        .getSharedSecret(hex.encode(privateKey), hex.encode(publicKey), true)
        .slice(1);
      const salt = new Uint8Array(
        await crypto.subtle.digest("SHA-256", sessionTranscriptBytes),
      );
      const infoAsBytes = stringToBytes(info);
      const result = await hkdf("sha256", ikm, salt, infoAsBytes, 32);

      return new CoseKey({
        keyOps: [KeyOps.Sign, KeyOps.Verify],
        keyType: KeyType.Oct,
        k: result,
        algorithm: MacAlgorithm.HS256,
      });
    },
  },

  cose: {
    mac0: {
      sign: async ({ jwk, mac0 }) =>
        hmac(sha256, asUint8Array(jwk.k ?? jwk.privateKey), asUint8Array(mac0.toBeAuthenticated)),
      verify: async ({ mac0, key }) => {
        if (!mac0.tag) {
          throw new Error("tag is required for mac0 verification");
        }

        return mac0.tag === hmac(
          sha256,
          asUint8Array(key.privateKey),
          asUint8Array(mac0.toBeAuthenticated),
        );
      },
    },
    sign1: {
      sign: async ({ jwk, sign1 }) => {
        const { data } = sign1.getRawSigningData();
        const hashed = sha256(asUint8Array(data));
        const sig = p256.sign(hashed, asUint8Array(Buffer.from(jwk.d, "base64url")));
        return sig.toCompactRawBytes();
      },
      verify: async ({ sign1, key }) => {
        if (!sign1.signature) {
          throw new Error("signature is required for sign1 verification");
        }

        const hashed = sha256(asUint8Array(sign1.toBeSigned));
        return p256.verify(
          asUint8Array(sign1.signature),
          hashed,
          asUint8Array(key.publicKey),
        );
      },
    },
  },

  x509: {
    getIssuerNameField: ({ certificate, field }) => {
      const parsed = new X509Certificate(certificate);
      return parsed.issuerName.getField(field);
    },
    getPublicKey: async ({ certificate, alg }) => {
      const parsed = new X509Certificate(certificate);
      const key = await importX509(parsed.toString(), alg, { extractable: true });
      return CoseKey.fromJwk(await exportJWK(key));
    },
    validateCertificateChain: async ({ trustedCertificates, x5chain: certificateChain }) => {
      if (certificateChain.length === 0) {
        throw new Error("Certificate chain is empty");
      }

      const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0]);
      const parsedCertificates = certificateChain.map(
        (certificate) => new x509.X509Certificate(certificate),
      );
      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: parsedCertificates,
      });

      const chain = await certificateChainBuilder.build(parsedLeafCertificate);
      let parsedChain = chain
        .map((certificate) => new x509.X509Certificate(certificate.rawData))
        .reverse();

      if (parsedChain.length !== certificateChain.length) {
        throw new Error("Could not parse the full chain. Likely due to incorrect ordering");
      }

      const parsedTrustedCertificates = trustedCertificates.map(
        (trustedCertificate) => new x509.X509Certificate(trustedCertificate),
      );
      const trustedCertificateIndex = parsedChain.findIndex((certificate) =>
        parsedTrustedCertificates.some((trustedCertificate) =>
          certificate.equal(trustedCertificate),
        ),
      );

      if (trustedCertificateIndex === -1) {
        throw new Error("No trusted certificate was found while validating the X.509 chain");
      }

      parsedChain = parsedChain.slice(0, trustedCertificateIndex);

      for (let i = 0; i < parsedChain.length; i++) {
        const certificate = parsedChain[i];
        const previousCertificate = parsedChain[i - 1];
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined;
        await certificate?.verify({ publicKey, date: new Date() });
      }
    },
  },
};
