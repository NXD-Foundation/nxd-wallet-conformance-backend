/**
 * IATA Resolution 792 (BCBP) helpers and airline boarding-pass SD-JWT claim builder.
 * Mandatory BCBP fields use Res 792 semantics/widths; display helpers are optional.
 */

export const DEFAULT_AIRLINE_BOARDING_PASS_CLAIMS = {
  // BCBP unique / header
  format_code: "M",
  number_of_legs: "1",
  passenger_name: "MATKALAINEN/NIKOS",
  electronic_ticket_indicator: "E",
  // BCBP mandatory per-leg
  pnr: "ABC123",
  from_airport: "ATH",
  to_airport: "HER",
  operating_carrier: "A3",
  flight_number: "0604",
  date_of_flight_julian: "213",
  compartment_code: "Y",
  seat: "014A",
  check_in_sequence_number: "00042",
  passenger_status: "0",
  // Canonical BCBP mandatory block (60 chars incl. conditional size "00")
  bcbp_data:
    "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0604 213Y014A00042000",
  // Optional display / wallet UX (not BCBP-mandatory)
  given_name: "NIKOS",
  family_name: "MATKALAINEN",
  carrier_name: "AEGEAN",
  departure_datetime: "2026-08-01T08:15:00+03:00",
  arrival_datetime: "2026-08-01T09:05:00+03:00",
  terminal: "Main",
  gate: "B12",
  boarding_time: "07:35",
  boarding_group: "2",
  ticket_number: "3901234567890",
  baggage_allowance: "1PC",
};

export const AIRLINE_BOARDING_PASS_CLAIM_KEYS = Object.keys(
  DEFAULT_AIRLINE_BOARDING_PASS_CLAIMS,
);

export function bcbpPadRight(value, width) {
  return String(value ?? "")
    .toUpperCase()
    .slice(0, width)
    .padEnd(width, " ");
}

export function bcbpPadSeat(value) {
  const raw = String(value ?? "")
    .toUpperCase()
    .replace(/\s+/g, "");
  if (!raw) return "0000";
  const match = raw.match(/^(\d+)([A-Z]?)$/);
  if (!match) return bcbpPadRight(raw, 4);
  return `${match[1]}${match[2] || ""}`.padStart(4, "0").slice(-4);
}

export function bcbpPadFlightNumber(value) {
  const raw = String(value ?? "")
    .trim()
    .toUpperCase();
  if (!raw) return "     ";

  // Accept "604", "0604", "A3 604", "A3604" — keep the flight numeric part only.
  const withCarrier = raw.match(
    /^([A-Z][A-Z0-9]|[0-9][A-Z])\s*(\d{1,4})$/,
  );
  const digits = withCarrier ? withCarrier[2] : raw.replace(/\D/g, "");
  if (!digits) return "     ";
  // Res 792: 5 chars — typically 4-digit zero-padded flight + trailing space
  return digits.slice(-4).padStart(4, "0").padEnd(5, " ");
}

export function bcbpJulianDay(isoOrJulian) {
  if (isoOrJulian == null || isoOrJulian === "") return "000";
  const asString = String(isoOrJulian).trim();
  if (/^\d{1,3}$/.test(asString)) return asString.padStart(3, "0");
  const d = new Date(asString);
  if (Number.isNaN(d.getTime())) return "000";
  const year = d.getUTCFullYear();
  const start = Date.UTC(year, 0, 0);
  const day = Math.floor(
    (Date.UTC(year, d.getUTCMonth(), d.getUTCDate()) - start) / 86_400_000,
  );
  return String(day).padStart(3, "0");
}

/**
 * Build the IATA Res 792 mandatory BCBP block (60 chars) for a single leg,
 * plus a 2-char hex conditional-size field (defaults to "00").
 */
export function buildIataBcbpDataString(source = {}, conditionalSizeHex = "00") {
  if (source.bcbp_data) return String(source.bcbp_data);

  const formatCode = String(source.format_code || "M").slice(0, 1).toUpperCase();
  const legs = String(source.number_of_legs || "1").slice(0, 1);
  const passengerName = bcbpPadRight(
    source.passenger_name ||
      (source.family_name || source.given_name
        ? `${source.family_name || ""}/${source.given_name || ""}`.replace(
            /^\/|\/$/g,
            "",
          )
        : ""),
    20,
  );
  const eTicket = String(source.electronic_ticket_indicator || "E")
    .slice(0, 1)
    .toUpperCase();
  const pnr = bcbpPadRight(source.pnr || "", 7);
  const from = bcbpPadRight(
    source.from_airport || source.from || "",
    3,
  ).slice(0, 3);
  const to = bcbpPadRight(source.to_airport || source.to || "", 3).slice(0, 3);
  const carrier = bcbpPadRight(
    source.operating_carrier || source.carrier_code || "",
    3,
  );
  const flight = bcbpPadFlightNumber(source.flight_number || source.flight);
  const julian = bcbpJulianDay(
    source.date_of_flight_julian || source.departure_datetime || source.date,
  );
  const compartment = String(
    source.compartment_code || source.cabin_class || "Y",
  )
    .slice(0, 1)
    .toUpperCase();
  const seat = bcbpPadSeat(source.seat);
  const sequence = String(
    source.check_in_sequence_number || source.sequence_number || "",
  )
    .replace(/\D/g, "")
    .padStart(5, "0")
    .slice(-5);
  const status = String(source.passenger_status || "0").slice(0, 1);
  const condSize = String(conditionalSizeHex || "00")
    .toUpperCase()
    .padStart(2, "0")
    .slice(-2);

  return `${formatCode}${legs}${passengerName}${eTicket}${pnr}${from}${to}${carrier}${flight}${julian}${compartment}${seat}${sequence}${status}${condSize}`;
}

/**
 * Map legacy / display offer fields onto BCBP claim names and normalize widths.
 */
export function normalizeAirlineBoardingPassSource(source = {}) {
  const out = { ...source };

  if (out.from && !out.from_airport) out.from_airport = out.from;
  if (out.to && !out.to_airport) out.to_airport = out.to;
  if (out.carrier_code && !out.operating_carrier) {
    out.operating_carrier = out.carrier_code;
  }
  if (out.sequence_number && !out.check_in_sequence_number) {
    out.check_in_sequence_number = out.sequence_number;
  }
  if (out.cabin_class && !out.compartment_code) {
    // Accept already-coded compartment; ignore marketing labels like "Economy"
    const code = String(out.cabin_class).trim();
    if (code.length === 1) out.compartment_code = code.toUpperCase();
  }

  if (!out.passenger_name && (out.family_name || out.given_name)) {
    out.passenger_name = `${String(out.family_name || "").toUpperCase()}/${String(
      out.given_name || "",
    ).toUpperCase()}`.replace(/^\/|\/$/g, "");
  }

  if (!out.date_of_flight_julian && out.departure_datetime) {
    out.date_of_flight_julian = bcbpJulianDay(out.departure_datetime);
  }

  if (out.seat) out.seat = bcbpPadSeat(out.seat);
  if (out.check_in_sequence_number) {
    out.check_in_sequence_number = String(out.check_in_sequence_number)
      .replace(/\D/g, "")
      .padStart(5, "0")
      .slice(-5);
  }
  if (out.flight_number != null && String(out.flight_number).trim() !== "") {
    // Persist the BCBP-facing flight number (digits / padded), not "A3 604"
    const padded = bcbpPadFlightNumber(out.flight_number).trimEnd();
    if (padded) out.flight_number = padded.padStart(4, "0");
  }

  return out;
}

export const getAirlineBoardingPassSDJWTData = () => {
  return getAirlineBoardingPassSDJWTDataWithPayload(null);
};

export const getAirlineBoardingPassSDJWTDataWithPayload = (payload) => {
  const rawSource =
    payload?.claims && typeof payload.claims === "object"
      ? payload.claims
      : payload || {};
  const sourceClaims = normalizeAirlineBoardingPassSource(rawSource);
  const explicitBcbp =
    Object.prototype.hasOwnProperty.call(rawSource, "bcbp_data") ||
    Object.prototype.hasOwnProperty.call(sourceClaims, "bcbp_data");

  const claims = {};
  for (const key of AIRLINE_BOARDING_PASS_CLAIM_KEYS) {
    claims[key] =
      sourceClaims[key] ?? DEFAULT_AIRLINE_BOARDING_PASS_CLAIMS[key];
  }

  if (!explicitBcbp) {
    const { bcbp_data: _ignored, ...structured } = claims;
    claims.bcbp_data = buildIataBcbpDataString(structured);
  }

  const disclosureFrame = {
    _sd: [...AIRLINE_BOARDING_PASS_CLAIM_KEYS],
  };

  return { claims, disclosureFrame };
};
