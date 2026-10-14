# VP request parameters

Use `/vp/request?profile=dcql&credential_profile=ts12-dpc-pid` to request an SD-JWT PID with the official EU base VCT `urn:eudi:pid:1`, per [PID Rulebook section 4.2](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md#42-note-on-vct).

The query requests `given_name`, `family_name`, `birthdate`, `place_of_birth`, `nationalities`, `issuing_authority`, and `issuing_country`. Its credential query ID is `ts12-dpc-pid`.

The preset also applies in CS-02 strict mode and with `profile=tx`. Existing `pid`, `arf-pid`, and `mdl` presets remain available.

For `POST /vp/dc-api/request`, send `"profile": "ts12-dpc-pid"` in the JSON body together with the payment fields. This profile requests the DPC payment credential plus PID with VCT `urn:eudi:pid:1`. PID claims and optional claim sets follow the existing payment profile. The request Origin must be authorized for this profile. Restart the service after changing DC API configuration.

DPC credential issuance also returns `display: [{ card: { alias, card_art, network_branding } }]` at response level. GRNET wallet core `v0.31.0-grnet.5` consumes this extension to render a payment card under Finance. `card_art` embeds the black Mastercard-style PNG as a data URI. It is display metadata, outside signed claims, and included inside credential-response encryption. No PAN or last-four digits are invented.
