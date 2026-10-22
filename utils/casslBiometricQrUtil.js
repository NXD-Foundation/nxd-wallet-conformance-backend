/**
 * CASSL biometric QR helpers and SD-JWT claim builder.
 * Encodes a mock biometric JSON payload as a PNG QR in the `picture` claim.
 */

import { createHash } from "crypto";
import fs from "fs";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { buildIataBcbpDataString } from "./airlineBoardingPassUtil.js";

/** Mock PID portrait (JPEG bytes) — see data/portraits/README.md */
const PID_PORTRAIT_JPEG = fs.readFileSync("./data/portraits/pid-portrait.jpg");

const BIOMETRIC_QR_CONFIG = {
  type: "png",
  ec_level: "H",
  size: 10,
  margin: 10,
};

async function encodeTextAsQrDataUri(text) {
  const code = qr.image(String(text), BIOMETRIC_QR_CONFIG);
  // Lowercase png matches the QR bitmap bytes. Claim key must be `picture`
  // (or `portrait`) for EUDI wallets to render the value as an image.
  return imageDataURI.encode(await streamToBuffer(code), "png");
}

/**
 * Mock CASSL biometric QR payload. The encrypted_template is derived from a
 * portrait image (full JPEG is too large for a scannable QR); we embed a
 * compact base64url digest + portrait prefix as a stand-in biometric template.
 */
export function portraitBytesFromDataUrl(dataUrl) {
  if (!dataUrl || typeof dataUrl !== "string") return null;
  const match = dataUrl.match(/^data:image\/[^;]+;base64,(.+)$/i);
  if (!match) return null;
  try {
    return Buffer.from(match[1], "base64");
  } catch {
    return null;
  }
}

export function buildEncryptedTemplateFromPortrait(portraitBytes) {
  const bytes = portraitBytes?.length ? portraitBytes : PID_PORTRAIT_JPEG;
  return Buffer.concat([
    createHash("sha256").update(bytes).digest(),
    bytes.subarray(0, Math.min(64, bytes.length)),
  ]).toString("base64url");
}

function buildBoardingPassDataString(source = {}) {
  if (source.boarding_pass_data) return String(source.boarding_pass_data);
  if (source.bcbp_data) return String(source.bcbp_data);
  const family = String(source.family_name || "").toUpperCase();
  const given = String(source.given_name || "").toUpperCase();
  const pnr = source.pnr || "";
  const flight = source.flight_number || source.flight || "";
  if (!family && !given && !pnr && !flight && !source.passenger_name) {
    return undefined;
  }
  return buildIataBcbpDataString(source);
}

/**
 * Map either a structured biometric QR JSON object or the flat offer payload
 * (boarding-pass + PID fields, with `picture` as the portrait source) into
 * overrides for {@link buildDefaultCasslBiometricQrPayload}.
 *
 * Important: flat `picture` is the PID/portrait input for the encrypted
 * template — not the issued QR image claim.
 */
export function mapSourceToBiometricQrOverrides(source = {}) {
  if (
    source.passenger ||
    source.journey ||
    source.biometric ||
    source.validity
  ) {
    const portraitBytes = portraitBytesFromDataUrl(
      source.portrait || source.picture,
    );
    return {
      version: source.version,
      passenger: source.passenger,
      journey: source.journey,
      biometric: {
        ...(source.biometric || {}),
        ...(portraitBytes
          ? {
              encrypted_template:
                buildEncryptedTemplateFromPortrait(portraitBytes),
            }
          : {}),
      },
      validity: source.validity,
      signature: source.signature,
    };
  }

  const name =
    source.passenger_name ||
    [source.given_name, source.family_name].filter(Boolean).join(" ") ||
    undefined;
  const portraitBytes = portraitBytesFromDataUrl(source.picture);
  const flightRaw = source.flight_number || source.flight;
  const flight = flightRaw
    ? String(flightRaw).replace(/\s+/g, "")
    : undefined;
  const date =
    source.flight_date ||
    (source.departure_datetime
      ? String(source.departure_datetime).slice(0, 10)
      : undefined);
  const departure =
    source.from_airport ||
    source.from ||
    source.departure ||
    source.airport_code;
  const boardingPassData = buildBoardingPassDataString(source);

  return {
    passenger: {
      ...(name ? { name } : {}),
      ...(source.document_number || source.document_reference
        ? {
            document_reference:
              source.document_number || source.document_reference,
          }
        : {}),
      identity_verified:
        source.identity_verified !== undefined
          ? Boolean(source.identity_verified)
          : true,
    },
    journey: {
      ...(flight ? { flight } : {}),
      ...(date ? { date } : {}),
      ...(departure ? { departure } : {}),
      ...(boardingPassData ? { boarding_pass_data: boardingPassData } : {}),
    },
    biometric: {
      ...(portraitBytes
        ? {
            encrypted_template:
              buildEncryptedTemplateFromPortrait(portraitBytes),
          }
        : {}),
      ...(source.enrolment_method
        ? { enrolment_method: source.enrolment_method }
        : {}),
      ...(source.biometric_session_id
        ? { session_id: source.biometric_session_id }
        : {}),
      ...(source.service_scopes ? { service_scopes: source.service_scopes } : {}),
    },
    validity: {
      ...(source.valid_from || source.not_before
        ? { not_before: source.valid_from || source.not_before }
        : {}),
      ...(source.valid_until || source.expires_at
        ? { expires_at: source.valid_until || source.expires_at }
        : {}),
    },
  };
}

export function buildDefaultCasslBiometricQrPayload(overrides = {}) {
  const now = new Date();
  const expires = new Date(now);
  expires.setDate(expires.getDate() + 1);

  const defaults = {
    version: "1",
    passenger: {
      name: "NIKOS MATKALAINEN",
      document_reference: "A01234567",
      identity_verified: true,
    },
    journey: {
      flight: "A3120",
      date: "2026-10-28",
      departure: "ATH",
      boarding_pass_data:
        "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0120 301Y014A00042000",
    },
    biometric: {
      modality: "face",
      encrypted_template: buildEncryptedTemplateFromPortrait(PID_PORTRAIT_JPEG),
      template_format: "mock-portrait-digest-v1",
      quality: "high",
      enrolment_method: "passport-plus-live-capture",
    },
    validity: {
      not_before: now.toISOString(),
      expires_at: expires.toISOString(),
    },
  };

  const merged = {
    version: overrides.version ?? defaults.version,
    passenger: { ...defaults.passenger, ...(overrides.passenger || {}) },
    journey: { ...defaults.journey, ...(overrides.journey || {}) },
    biometric: { ...defaults.biometric, ...(overrides.biometric || {}) },
    validity: { ...defaults.validity, ...(overrides.validity || {}) },
  };

  if (overrides.signature) {
    merged.signature = overrides.signature;
  } else {
    const signatureInput = JSON.stringify({
      version: merged.version,
      passenger: merged.passenger,
      journey: merged.journey,
      biometric: merged.biometric,
      validity: merged.validity,
    });
    merged.signature = createHash("sha256")
      .update(signatureInput)
      .digest("base64url");
  }

  return merged;
}

export const getCasslBiometricQrSDJWTData = async () => {
  return getCasslBiometricQrSDJWTDataWithPayload(null);
};

export const getCasslBiometricQrSDJWTDataWithPayload = async (payload) => {
  const source =
    payload?.claims && typeof payload.claims === "object"
      ? payload.claims
      : payload || {};

  const qrPayloadSource =
    source.biometric_qr_payload && typeof source.biometric_qr_payload === "object"
      ? source.biometric_qr_payload
      : source.qr_payload && typeof source.qr_payload === "object"
        ? source.qr_payload
        : null;

  // Pre-rendered QR only when explicitly supplied under qr_* keys.
  // Flat `picture` is the portrait used to derive encrypted_template.
  let picture = source.qr_code ?? source.picture_qr ?? source.qr_picture;
  if (!picture) {
    const overrides = qrPayloadSource
      ? mapSourceToBiometricQrOverrides(qrPayloadSource)
      : mapSourceToBiometricQrOverrides(source);
    const biometricPayload = buildDefaultCasslBiometricQrPayload(overrides);
    picture = await encodeTextAsQrDataUri(JSON.stringify(biometricPayload));
  }

  const claims = { picture };
  const disclosureFrame = { _sd: ["picture"] };

  return { claims, disclosureFrame };
};
