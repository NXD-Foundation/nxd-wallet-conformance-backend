import fs from "fs";

const DPC_VCT = "https://webuildconsortium.eu/sca/sca-card-dpc/1.0";
const artwork = `data:image/png;base64,${fs.readFileSync(
  new URL("../data/img/credentials/mastercard-dpc.png", import.meta.url),
).toString("base64")}`;

// GRNET / SCA-Card rulebook extension: display belongs in the credential
// response, outside the signed credential (and inside response encryption).
export function withDpcCardDisplay(payload, credentialType) {
  if (credentialType !== DPC_VCT) return payload;
  return {
    ...payload,
    display: [{
      card: {
        alias: "Mastercard SCA-Card (DPC)",
        card_art: [{ theme: "DEFAULT", image_url: artwork }],
        network_branding: {
          network: "mastercard",
          branding: { name: "Mastercard" },
        },
      },
    }],
  };
}
