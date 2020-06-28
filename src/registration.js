const { decodeAllSync } = require('cbor');

const { randomBase64Buffer } = require('./utils');
const { getChallengeFromClientData } = require('./getChallengeFromClientData');
const { parseAndroidSafetyNetKey } = require('./authenticatorKey/parseAndroidSafetyNetKey');
const { parseFidoU2FKey } = require('./authenticatorKey/parseFidoU2FKey');
const { parseFidoPackedKey } = require('./authenticatorKey/parseFidoPackedKey');
const { validateRegistrationCredentials } = require('./validation');

const parseAuthenticatorKey = (webAuthnResponse) => {
    const authenticatorKeyBuffer = Buffer.from(
        webAuthnResponse.attestationObject,
        'base64'
    );
    const authenticatorKey = decodeAllSync(authenticatorKeyBuffer)[0];

    if (authenticatorKey.fmt === 'android-safetynet') {
        return parseAndroidSafetyNetKey(
            authenticatorKey,
            webAuthnResponse.clientDataJSON
        );
    }

    if (authenticatorKey.fmt === 'fido-u2f') {
        return parseFidoU2FKey(
            authenticatorKey,
            webAuthnResponse.clientDataJSON
        );
    }

    if (authenticatorKey.fmt === 'packed') {
        return parseFidoPackedKey(
            authenticatorKey,
            webAuthnResponse.clientDataJSON
        );
    }

    return undefined;
};

exports.parseRegisterRequest = (body) => {
    if (!validateRegistrationCredentials(body)) {
        return {};
    }
    const challenge = getChallengeFromClientData(body.response.clientDataJSON);
    const key = parseAuthenticatorKey(body.response);

    return {
        challenge,
        key,
    };
};

exports.generateRegistrationChallenge = ({ relyingParty, user, authenticator = 'platform', attestation = 'direct', userVerification = 'preferred', timeout = 60000, } = {}) => {
    if (!relyingParty || !relyingParty.name || typeof relyingParty.name !== 'string') {
        throw new Error('The typeof relyingParty.name should be a string');
    }

    if (!user || !user.id || !user.name || typeof user.id !== 'string' || typeof user.name !== 'string') {
        throw new Error('The user should have an id (string) and a name (string)');
    }

    if (!authenticator) {
        authenticator = undefined;
    }
    if (!(['cross-platform', 'platform', undefined].includes(authenticator))) {
        authenticator = 'platform';
    }

    if (!(['none', 'direct', 'indirect'].includes(attestation))) {
        attestation = 'direct';
    }

    if (!(['preferred', 'required', 'discouraged'].includes(userVerification))) {
        userVerification = 'preferred';
    }

    if (!Number.isInteger (timeout)) {
        timeout = 60000;
    }

    return {
        challenge: randomBase64Buffer(32),
        rp: {
            id: relyingParty.id,
            name: relyingParty.name
        },
        user: {
            id: Buffer.from(user.id).toString('base64'),
            displayName: user.displayName || user.name,
            name: user.name
        },
        attestation,
        pubKeyCredParams: [
            // Support FIDO2 devices, MACOSX, default
            {
                type: 'public-key',
                alg: -7 // "ES256" IANA COSE Algorithms registry
            },
            // Support Windows devices (Hello) 
            {
                type: 'public-key',
                alg: -257 // "RS256"
            },
            // Some other algorithms supposed by webauthn.io
            {type: "public-key", alg: -35},
            {type: "public-key", alg: -36},
            {type: "public-key", alg: -258},
            {type: "public-key", alg: -259},
            {type: "public-key", alg: -37},
            {type: "public-key", alg: -38},
            {type: "public-key", alg: -39},
            {type: "public-key", alg: -8},
        ],
        authenticatorSelection: {
            authenticatorAttachment: authenticator,
            requireResidentKey: false,
            userVerification,
        },
        extensions: {
            txAuthSimple: "",
        },
        timeout,
    };
};
