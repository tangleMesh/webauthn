const base64url = require('base64url');

exports.getChallengeFromClientData = (clientDataJSON) => {
    const clientDataBuffer = Buffer.from(clientDataJSON, 'base64');
    const clientData = JSON.parse(clientDataBuffer.toString());
    const challenge = Buffer.from(clientData.challenge, 'base64');
    return base64url (challenge);
};
