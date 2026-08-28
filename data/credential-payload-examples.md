# Credential payload examples

Mock **issued claim payloads** for credentials published in
[`issuer-config.json`](./issuer-config.json). These are the claim objects built in
[`utils/credPayloadUtil.js`](../utils/credPayloadUtil.js) (and related helpers)
before SD-JWT signing, JWT VC wrapping, mdoc encoding, or X.509 attribute
certificate serialization.

This document is a **test-service reference**, not a normative schema. For
metadata, formats, and advertised claim paths, use issuer metadata and the
linked rulebooks in `docs/`.

## Conventions

| Symbol | Meaning |
| --- | --- |
| `<data-url>` | Base64 data URL (JPEG/PNG). PID portrait source: [`portraits/pid-portrait.jpg`](./portraits/pid-portrait.jpg). |
| `<uuid>` | Runtime-generated subject id (often a UUID or wallet holder binding). |
| `<serverURL>` | Issuer base URL from deployment configuration. |
| `…` | Additional fields omitted for brevity. |

**Offer input vs issued claims:** Pre-authorized and batch offer routes may accept
a `payload` or `credentialPayload` object. Where normalization happens at
issuance (Accommodation Voucher, European Disability Card, CASSL biometric QR,
Hotel Pass), both shapes are shown when they differ.

**Selective disclosure:** SD-JWT credentials list only the claim keys that appear
in the issued payload. The `_sd` disclosure frame in code may expose a subset or
superset for testing; see issuer metadata `claims[].path` for advertised paths.

---

## PID — SD-JWT (`dc+sd-jwt`)

**Configuration ids:** `urn:eu.europa.ec.eudi:pid:1`, `ETSIRfc001PidVcSdJwt`,
`VerifiablePIDSDJWT`, `VerifiablePIDSDJWTAttestation`, `VerifiableIdCardJwtVc`

**VCT:** `urn:eu.europa.ec.eudi:pid:1`

```json
{
  "given_name": "Hanna",
  "family_name": "Matkalainen",
  "birthdate": "2005-07-01",
  "place_of_birth": {
    "country": "FI",
    "region": "Uusimaa",
    "locality": "Helsinki"
  },
  "nationalities": ["FI"],
  "picture": "<data-url>",
  "address": {
    "formatted": "Mannerheimintie 1, 00100 Helsinki",
    "country": "FI",
    "region": "Uusimaa",
    "locality": "Helsinki",
    "postal_code": "00100",
    "street_address": "Mannerheimintie 1",
    "house_number": "1"
  },
  "personal_administrative_number": "123456-789A",
  "birth_family_name": "Virtanen",
  "birth_given_name": "Hanna Maria",
  "sex": 2,
  "email": "hanna.matkalainen@example.com",
  "phone_number": "+358401234567",
  "issuing_authority": "Digital and Population Data Services Agency",
  "issuing_country": "FI",
  "date_of_issuance": "2026-08-26",
  "date_of_expiry": "2036-08-26",
  "document_number": "A01234567",
  "issuing_jurisdiction": "FI-18",
  "trust_anchor": "https://example.com/trustanchors/pid/",
  "attestation_legal_category": "PID"
}
```

---

## PID — mdoc (`mso_mdoc`)

**Configuration id:** `urn:eu.europa.ec.eudi:pid:1:mso_mdoc`

**Doctype / namespace:** `urn:eu.europa.ec.eudi:pid:1`

Issued namespace payload (attribute names differ from SD-JWT PID):

```json
{
  "urn:eu.europa.ec.eudi:pid:1": {
    "given_name": "Hanna",
    "family_name": "Matkalainen",
    "birth_date": "2005-07-01",
    "place_of_birth": {
      "country": "FI",
      "region": "Uusimaa",
      "locality": "Helsinki"
    },
    "nationality": ["FI"],
    "portrait": "<raw JPEG bytes — not a data URL>",
    "resident_address": "Mannerheimintie 1, 00100 Helsinki",
    "resident_country": "FI",
    "resident_state": "Uusimaa",
    "resident_city": "Helsinki",
    "resident_postal_code": "00100",
    "resident_street": "Mannerheimintie 1",
    "personal_administrative_number": "123456-789A",
    "family_name_birth": "Virtanen",
    "given_name_birth": "Hanna Maria",
    "sex": 2,
    "email_address": "hanna.matkalainen@example.com",
    "mobile_phone_number": "+358401234567",
    "issuing_authority": "Digital and Population Data Services Agency",
    "issuing_country": "FI",
    "issuance_date": "2026-08-26",
    "expiry_date": "2036-08-26",
    "document_number": "A01234567",
    "issuing_jurisdiction": "FI-18",
    "trust_anchor": "https://example.com/trustanchors/pid/",
    "attestation_legal_category": "PID"
  }
}
```

---

## PID — JWT VC (`jwt_vc_json`)

**Configuration id:** `ETSIRfc001PidVcJwt`

Legacy JWT VC envelope (persona-dependent `credentialSubject`):

```json
{
  "iss": "<serverURL>",
  "sub": "<wallet-holder-did>",
  "iat": 1756195200,
  "exp": 1758787200,
  "jti": "urn:did:1904a925-38bd-4eda-b682-4b5e3ca9d4bc",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://europa.eu/2018/credentials/eudi/pid/v1"
    ],
    "type": ["PID"],
    "issuer": "<serverURL>",
    "id": "<wallet-holder-did>",
    "issuanceDate": "2026-08-26T00:00:00.000Z",
    "expirationDate": "2026-09-25T00:00:00.000Z",
    "validFrom": "2026-08-26T00:00:00.000Z",
    "credentialSubject": {
      "id": "<wallet-holder-did>",
      "given_name": "Hanna",
      "family_name": "Matkalainen"
    }
  }
}
```

---

## PID — X.509 Attribute Certificate (`x509_attr`)

**Configuration id:** `ETSIRfc001PidX509Attr`

The attribute value is a JSON blob (pilot OID) with the same semantic content as
SD-JWT PID claims:

```json
{
  "given_name": "Hanna",
  "family_name": "Matkalainen",
  "birthdate": "2005-07-01",
  "nationalities": ["FI"],
  "picture": "<data-url>",
  "issuing_country": "FI"
}
```

(Full claim set matches the SD-JWT PID example above.)

---

## Photo ID (`PhotoID`)

**Configuration id:** `PhotoID` · **VCT:** `eu.europa.ec.eudi.photoid.1`

```json
{
  "id": "<uuid>",
  "iss": "<serverURL>",
  "iat": 1756195200,
  "exp": 1758787200,
  "vct": "eu.europa.ec.eudi.photoid.1",
  "iso23220": {
    "family_name_unicode": "Matkalainen",
    "given_name_unicode": "Hanna",
    "birth_date": "2005-01-02",
    "portrait": "<base64 face sample from data/face.data>",
    "issue_date": "2023-01-01",
    "expiry_date": "2027-01-01",
    "issuing_authority_unicode": "Finland Test Authority",
    "issuing_country": "FIN",
    "sex": "2",
    "nationality": "FIN",
    "document_number": "ABC1234567",
    "name_at_birth": "Hanna Matkalainen",
    "birthplace": "Roveaniemi",
    "portrait_capture_date": "2023-02-01T10:00:00Z",
    "resident_address_unicode": "123 Elm Street",
    "resident_city_unicode": "Roveaniemi",
    "resident_postal_code": "W12345",
    "resident_country": "FI",
    "age_over_18": true,
    "age_in_years": 33,
    "age_birth_year": 1990,
    "family_name_latin1": "Matkalainen",
    "given_name_latin1": "Hanna"
  },
  "photoid": {
    "person_id": "PERSON-98765",
    "birth_country": "FI",
    "birth_state": "Roveaniemi",
    "birth_city": "Roveaniemi",
    "administrative_number": "ADMIN-123",
    "resident_street": "123 Elm Street",
    "resident_house_number": "12",
    "travel_document_number": "XP8271602",
    "resident_state": "Roveaniemi"
  },
  "dtc": {
    "dtc_version": "1.0.0",
    "dtc_dg1": "Full-MRZ-data-placeholder",
    "dtc_dg2": "<base64>",
    "dtc_sod": "<base64>",
    "dtc_dg3": "base64-binary-dg3",
    "dtc_dg4": "base64-binary-dg4",
    "dtc_dg16": "base64-binary-dg16",
    "dg_content_info": "base64-dtcContentInfo"
  }
}
```

---

## Pseudonym Credential (`PCD`)

**Configuration id:** `PCD` · **VCT:** `eu.europa.ec.eudi.pcd.1`

```json
{
  "id": "<uuid>",
  "iss": "<serverURL>",
  "iat": 1756195200,
  "exp": 1758787200,
  "vct": "eu.europa.ec.eudi.pcd.1",
  "surname": "Matkalainen",
  "given_name": "Hanna",
  "phone": "+358 457 123 4567",
  "email_address": "hanna@suomil.com",
  "city_address": "Rovaniemi",
  "street_address": "Tähtikuja 1",
  "country_address": "Finland"
}
```

---

## Student ID (`VerifiableStudentIDSDJWT`)

**Configuration id:** `VerifiableStudentIDSDJWT` · **VCT:** `VerifiableStudentIDSDJWT`

```json
{
  "id": "<uuid>",
  "identifier": "hanna@aegean.gr",
  "schacPersonalUniqueCode": [
    "urn:schac:personalUniqueCode:int:esi:university.edu:12345"
  ],
  "schacPersonalUniqueID": "urn:schac:personalUniqueID:us:12345",
  "schacHomeOrganization": "university.edu",
  "familyName": "Matkalainen",
  "firstName": "Hanna",
  "displayName": "Hanna Matkalainen",
  "dateOfBirth": "01.07.2005",
  "commonName": "Hanna Matkalainen",
  "mail": "hanna@aegean.gr",
  "eduPersonPrincipalName": "hanna@aegean.gr",
  "eduPersonPrimaryAffiliation": "student",
  "eduPersonAffiliation": ["member", "student"],
  "eduPersonScopedAffiliation": ["student@university.edu"],
  "eduPersonAssurance": [
    "https://wiki.refeds.org/display/ASS/REFEDS+Assurance+Framework+ver+1.0"
  ]
}
```

Offer routes may pass OpenID Connect-style names; they are mapped at issuance
(`given_name` → `firstName`, `family_name` → `familyName`, etc.).

---

## ePassport (`VerifiableePassportCredentialSDJWT`)

**Configuration id:** `VerifiableePassportCredentialSDJWT`

```json
{
  "id": "<uuid>",
  "electronicPassport": {
    "dataGroup1": {
      "birthdate": "1990-01-01",
      "docTypeCode": "P",
      "expiryDate": "2030-01-01",
      "genderCode": "M",
      "holdersName": "John Doe",
      "issuerCode": "GR",
      "natlText": "Hellenic",
      "passportNumberIdentifier": "123456789"
    },
    "dataGroup15": {
      "activeAuthentication": {
        "publicKeyBinaryObject": "somePublicKeyUri"
      }
    },
    "dataGroup2EncodedFaceBiometrics": {
      "faceBiometricDataEncodedPicture": "someBiometricUri"
    }
  }
}
```

---

## Ferry boarding pass (`VerifiableFerryBoardingPassCredentialSDJWT`)

**Configuration id:** `VerifiableFerryBoardingPassCredentialSDJWT`

```json
{
  "id": "<uuid>",
  "identifier": "John Doe",
  "ticketQR": "<data-url PNG/JPEG QR>",
  "ticketNumber": "ABC123456789",
  "ticketLet": "A",
  "lastName": "Doe",
  "firstName": "John",
  "seatType": "Economy",
  "seatNumber": "12A",
  "departureDate": "2023-11-30",
  "departureTime": "13:07:34",
  "arrivalDate": "2023-11-30",
  "arrivalTime": "15:30:00",
  "arrivalPort": "NYC",
  "vesselDescription": "Ferry XYZ"
}
```

---

## Verifiable receipt (`VerifiableReceipt`)

**Configuration id:** `VerifiableReceipt` · **VCT:** `VerifiablevReceiptSDJWT`

Flat dot-path claim keys (UBL-inspired mock receipt):

```json
{
  "id": "<uuid>",
  "monetary_total.line_extension_amount": 150.75,
  "monetary_total.tax_inclusive_amount": 180.9,
  "monetary_total.payable_amount": 180.9,
  "tax_total.tax_subtotal.tax_amount": 30.15,
  "tax_total.tax_subtotal.tax_category.tax_scheme.name": "Standard VAT",
  "tax_total.tax_subtotal.percent": 20,
  "tax_total.tax_amount": 30.15,
  "address.street_name": "123 Main Street",
  "address.city_name": "Sample City",
  "address.postcode": "SC12345",
  "address.country_identifier": "GB",
  "payment_means.payment_means_code": "PM01",
  "payment_means.card_account.network_id": "VISA",
  "payment_means.card_account.account_number_id": "411111******1111",
  "item_property.item_property_name": "Color",
  "item_property.value": "Red",
  "purchase_receipt.id": "PR123456789",
  "purchase_receipt.issue_date": "2024-04-27",
  "purchase_receipt.document_currency_code": "GBP",
  "purchase_receipt.legal_monetary_total": 180.9,
  "purchase_receipt.seller_supplier_party.supplier_party_id": "SPID123456",
  "purchase_receipt.tax_included_indicator": true,
  "purchase_receipt.payment.paid_amount": 180.9,
  "purchase_receipt.payment.authorization_id": "AUTH123456789",
  "purchase_receipt.payment.transaction_id": "TXN123456789",
  "purchase_receipt.purchase_receipt_line.id": "PRL123456789",
  "purchase_receipt.purchase_receipt_line.quantity": 2,
  "purchase_receipt.purchase_receipt_line.tax_inclusive_line_extension_amount": 80.45,
  "purchase_receipt.purchase_receipt_line.item.commodity_classification.item_classification_code": "ICC67890",
  "delivery.actual_delivery_date": "2024-04-28",
  "delivery.actual_delivery_time": "14:30",
  "party_name.name": "Sample Seller Ltd.",
  "party_identification.id": "PID123456789"
}
```

Custom offer payloads are merged verbatim when provided via `credentialPayload`.

---

## Payment wallet attestation (`PaymentWalletAttestation`)

**Configuration id:** `PaymentWalletAttestation` · **VCT:** `PaymentWalletAttestation`

```json
{
  "aud": "<serverURL>/.well-known/oauth-authorization-server",
  "sub": "PSP-account-identifier",
  "id": "PSP-account-identifier",
  "fundingSource": {
    "type": "card",
    "parLastFour": "0010",
    "panLastFour": "0010",
    "iin": "401636",
    "aliasId": "alias-12345",
    "scheme": "Visa",
    "currency": "EUR",
    "icon": "https://cdn4.iconfinder.com/data/icons/flat-brand-logo-2/512/visa-512.png"
  }
}
```

Selectively disclosable keys include `parLastFour`, `panLastFour`, `iin`,
`aliasId`, `scheme`, `icon`, and `currency`.

---

## Portable documents A1 / A2 (`VerifiablePortableDocumentA1SDJWT`, `VerifiablePortableDocumentA2SDJWT`)

**Configuration ids:** `VerifiablePortableDocumentA1SDJWT`, `VerifiablePortableDocumentA2SDJWT`

Generic pilot placeholder:

```json
{
  "given_name": "John",
  "last_name": "Doe"
}
```

---

## Loyalty card (`LoyaltyCard`)

**Configuration id:** `LoyaltyCard` · **VCT:** `LoyaltyCard`

Offer input uses flat dot-path keys; issued claims are nested:

**Offer input example:**

```json
{
  "customer.first_name": "Hanna",
  "customer.last_name": "Matkalainen",
  "customer.nationality": "FI",
  "customer.address": "Mannerheimintie 1",
  "customer.city": "Helsinki",
  "customer.zip_code": "00100",
  "customer.phone": "+358401234567",
  "customer.mobile": "+358401234567",
  "customer.birth_date": "2005-07-01",
  "customer.email": "hanna@example.com",
  "loyalty_card.id": "FFC-123456",
  "loyalty_card.issue_date": "2026-01-15",
  "loyalty_card.status": "active",
  "loyalty_card.type": "gold",
  "portfolio.available_points": 12500,
  "portfolio.available_miles": 4200,
  "portfolio.available_wallet": 50.0,
  "portfolio.last_updated": "2026-08-26T10:00:00Z",
  "organization.name": "Fast Friends Airlines",
  "organization.id": "ORG-001",
  "organization.country": "FI",
  "credential.type": "LoyaltyCard",
  "credential.issuer": "<serverURL>",
  "credential.issuance_date": "2026-01-15",
  "credential.expiry_date": "2031-01-14"
}
```

**Issued claims:**

```json
{
  "id": "<uuid>",
  "customer": {
    "first_name": "Hanna",
    "last_name": "Matkalainen",
    "nationality": "FI",
    "address": "Mannerheimintie 1",
    "city": "Helsinki",
    "zip_code": "00100",
    "phone": "+358401234567",
    "mobile": "+358401234567",
    "birth_date": "2005-07-01",
    "email": "hanna@example.com"
  },
  "loyalty_card": {
    "id": "FFC-123456",
    "issue_date": "2026-01-15",
    "status": "active",
    "type": "gold"
  },
  "portfolio": {
    "available_points": 12500,
    "available_miles": 4200,
    "available_wallet": 50.0,
    "last_updated": "2026-08-26T10:00:00Z"
  },
  "organization": {
    "name": "Fast Friends Airlines",
    "id": "ORG-001",
    "country": "FI"
  },
  "credential": {
    "type": "LoyaltyCard",
    "issuer": "<serverURL>",
    "issuance_date": "2026-01-15",
    "expiry_date": "2031-01-14"
  }
}
```

---

## Accommodation Voucher (`booking_reference_credential`)

**Configuration id:** `booking_reference_credential` · **VCT:** `booking_reference_credential`

Display name: **Accommodation Voucher**.

**Default issued claims:**

```json
{
  "id": "<uuid>",
  "reservationReference": "BR-2026-00042",
  "supplierReference": "SUP-2026-00001",
  "property": {
    "id": "hotel-123",
    "name": "Example Hotel Athens"
  },
  "stay": {
    "checkInDate": "2026-06-12",
    "checkOutDate": "2026-06-15"
  },
  "room": {
    "type": "Standard Double"
  },
  "ratePlanCode": "BAR",
  "reservationStatus": "Confirmed",
  "voucherReference": "VCH-2026-00042",
  "guest": {
    "givenName": "Hanna",
    "familyName": "Matkalainen"
  }
}
```

**Legacy offer input** (translated at issuance):

```json
{
  "booking_reference": "OTA-MS62DP17-VQPSKP",
  "hotel_id": "9213",
  "hotel_name": "Test Hotel Rhodes",
  "arrival_date": "2026-07-31",
  "departure_date": "2026-08-04",
  "booking_platform": "SEDIT-X OTA Booking Portal",
  "given_name": "Hanna",
  "family_name": "Matkalainen"
}
```

**Canonical offer input:**

```json
{
  "reservationReference": "OTA-MS62DP17-VQPSKP",
  "supplierReference": "SEDIT-X OTA Booking Portal",
  "property": { "id": "9213", "name": "Test Hotel Rhodes" },
  "stay": { "checkInDate": "2026-07-31", "checkOutDate": "2026-08-04" },
  "guest": { "givenName": "Hanna", "familyName": "Matkalainen" }
}
```

---

## Airline PNR (`airline_pnr_credential`)

**Configuration id:** `airline_pnr_credential` · **VCT:** `urn:eu.aptitude:airline.pnr:1`

Minimal record-locator credential (PNR only in default mock):

```json
{
  "pnr": "Q7X2LM",
  "from": "ATH",
  "to": "RHO",
  "flight_date": "2026-07-31",
  "airline_name": "Aegean Airlines"
}
```

**Offer input example:**

```json
{
  "pnr": "Q7X2LM"
}
```

---

## Airline boarding pass (`airline_boarding_pass`)

**Configuration id:** `airline_boarding_pass` · **VCT:** `urn:eu.aptitude:airline.boardingpass:1`

IATA Resolution 792 (BCBP) field semantics:

```json
{
  "format_code": "M",
  "number_of_legs": "1",
  "passenger_name": "MATKALAINEN/NIKOS",
  "electronic_ticket_indicator": "E",
  "pnr": "ABC123",
  "from_airport": "ATH",
  "to_airport": "HER",
  "operating_carrier": "A3",
  "flight_number": "0604",
  "date_of_flight_julian": "213",
  "compartment_code": "Y",
  "seat": "014A",
  "check_in_sequence_number": "00042",
  "passenger_status": "0",
  "bcbp_data": "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0604 213Y014A00042000",
  "given_name": "NIKOS",
  "family_name": "MATKALAINEN",
  "carrier_name": "AEGEAN",
  "departure_datetime": "2026-08-01T08:15:00+03:00",
  "arrival_datetime": "2026-08-01T09:05:00+03:00",
  "terminal": "Main",
  "gate": "B12",
  "boarding_time": "07:35",
  "boarding_group": "2",
  "ticket_number": "3901234567890",
  "baggage_allowance": "1PC"
}
```

**Offer input example** (partial — `bcbp_data` is derived when omitted):

```json
{
  "format_code": "M",
  "number_of_legs": "1",
  "passenger_name": "MATKALAINEN/NIKOS",
  "electronic_ticket_indicator": "E",
  "pnr": "ABC123",
  "from_airport": "ATH",
  "to_airport": "HER",
  "operating_carrier": "A3",
  "flight_number": "0604",
  "date_of_flight_julian": "213",
  "compartment_code": "Y",
  "seat": "014A",
  "check_in_sequence_number": "00042",
  "passenger_status": "0"
}
```

---

## Hotel Pass (`room_key_credential`)

**Configuration id:** `room_key_credential` · **VCT:** `room_key_credential`

Display name: **Hotel Pass**. Visual QR pass — not a cryptographic room-key credential.

**Default issued claims** (`reservationReference` is used to render the QR; it is
not included in the issued payload):

```json
{
  "id": "<uuid>",
  "room_number": "412",
  "picture": "<data-url PNG QR encoding reservation reference>"
}
```

**Offer input example:**

```json
{
  "room_number": "412",
  "reservationReference": "RES-2026-001234"
}
```

Legacy alias: `reservationId` (same role as `reservationReference`). Pre-rendered
`picture` or `qr_code` data URLs are accepted instead of generating a QR.

---

## European Disability Card (`european_disability_card`)

**Configuration id:** `european_disability_card` · **VCT:** `urn:eu.europa.ec.eudi:edc:1`

```json
{
  "id": "<uuid>",
  "family_name": "Matkalainen",
  "given_name": "Hanna",
  "birth_date": "1990-05-23",
  "serial_number": "EDC-FI-2026-0001234",
  "issue_date": "2026-01-15",
  "expiry_date": "2031-01-14",
  "issuing_country": "FI",
  "portrait": "<data-url>",
  "assistant_entitlement": true,
  "disability_status_recognised": true
}
```

Legacy input aliases (`surname`, `forename`, `date_of_birth`, `file_number`,
`assistant_indicator`, `picture`) are normalized at issuance.

---

## CASSL biometric QR (`cassl_biometric_qr`)

**Configuration id:** `cassl_biometric_qr` · **VCT:** `urn:eu.aptitude:cassl.biometricqr:1`

Issued payload is a single QR image claim. The QR encodes a JSON biometric
envelope (default structure below). Flat offer fields (`given_name`, `family_name`,
`pnr`, `flight_number`, `picture` as portrait source, etc.) are mapped into that
envelope when no pre-rendered `qr_code` / `picture_qr` is supplied.

**Issued claims:**

```json
{
  "picture": "<data-url PNG QR encoding biometric JSON>"
}
```

**QR payload embedded in `picture` (default mock):**

```json
{
  "version": "1",
  "passenger": {
    "name": "NIKOS MATKALAINEN",
    "document_reference": "A01234567",
    "identity_verified": true
  },
  "journey": {
    "flight": "A3120",
    "date": "2026-10-28",
    "departure": "ATH",
    "boarding_pass_data": "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0120 301Y014A00042000"
  },
  "biometric": {
    "modality": "face",
    "encrypted_template": "<base64url mock template derived from portrait>",
    "template_format": "mock-portrait-digest-v1",
    "quality": "high",
    "enrolment_method": "passport-plus-live-capture"
  },
  "validity": {
    "not_before": "2026-08-26T07:00:00.000Z",
    "expires_at": "2026-08-27T07:00:00.000Z"
  },
  "signature": "<base64url SHA-256 over canonical JSON>"
}
```

**Structured offer input alternative:**

```json
{
  "biometric_qr_payload": {
    "passenger": { "name": "NIKOS MATKALAINEN", "document_reference": "A01234567" },
    "journey": { "flight": "A3120", "date": "2026-10-28", "departure": "ATH" }
  }
}
```

---

## Alliance ID (legacy JWT VC)

Not published in current `issuer-config.json`, but supported in
`credPayloadUtil.js` for legacy flows:

```json
{
  "id": "<uuid>",
  "identifier": {
    "schemeID": "European Student Identifier",
    "value": "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ",
    "id": "urn:schac:europeanUniversityAllianceCode:int:euai:ERUA:universityXYZ"
  }
}
```

---

## Source of truth

When examples drift from runtime behaviour, trust the builders in
[`utils/credPayloadUtil.js`](../utils/credPayloadUtil.js),
[`utils/airlineBoardingPassUtil.js`](../utils/airlineBoardingPassUtil.js), and
[`utils/casslBiometricQrUtil.js`](../utils/casslBiometricQrUtil.js), plus the
credential-type switch in
[`utils/credGenerationUtils.js`](../utils/credGenerationUtils.js).
