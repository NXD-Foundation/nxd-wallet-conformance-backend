import { expect } from 'chai';
import fs from 'fs';
import { withDpcCardDisplay } from '../utils/dpcCardDisplay.js';

const dpc = 'https://webuildconsortium.eu/sca/sca-card-dpc/1.0';

describe('GRNET DPC credential response artwork', () => {
  it('includes the response display.card path GRNET uses to recognize a Finance card', () => {
    const response = withDpcCardDisplay({ credentials: [{ credential: 'signed-token' }], notification_id: 'notification' }, dpc);
    const wireResponse = JSON.parse(JSON.stringify(response));
    expect(wireResponse.credentials).to.deep.equal([{ credential: 'signed-token' }]);
    expect(wireResponse.notification_id).to.equal('notification');
    const [entry] = wireResponse.display;
    expect(entry.card.alias).to.equal('Mastercard SCA-Card (DPC)');
    expect(entry.card.network_branding.network).to.equal('mastercard');
    expect(entry.card.card_art[0].theme).to.equal('DEFAULT');
    const image = entry.card.card_art[0].image_url;
    expect(image).to.match(/^data:image\/png;base64,/);
    expect(Buffer.from(image.split(',')[1], 'base64').equals(fs.readFileSync('./data/img/credentials/mastercard-dpc.png'))).to.equal(true);
    expect(entry.card).not.to.have.property('last_four');
  });

  it('adds the same artwork to deferred DPC responses', () => {
    const response = withDpcCardDisplay({ credential: 'deferred-token' }, dpc);
    expect(response.credential).to.equal('deferred-token');
    expect(response.display[0].card.card_art).to.have.length(1);
  });

  it('does not brand PID or other SCA credential responses as Mastercard', () => {
    for (const type of ['urn:eudi:pid:1', 'https://webuildconsortium.eu/sca/sca-iban/1.0']) {
      expect(withDpcCardDisplay({ credentials: [{ credential: 'token' }] }, type)).not.to.have.property('display');
    }
  });
});
