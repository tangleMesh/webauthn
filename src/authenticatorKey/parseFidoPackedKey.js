const { X509 } = require('jsrsasign');
const NodeRSA   = require('node-rsa');
const elliptic  = require('elliptic');
const { createVerify } = require('crypto');
const cbor = require('cbor');
const base64url = require('base64url');


const {
    hash,
    pemToBase64,
    convertASN1toPEM,
    convertCOSEPublicKeyToRawPKCSECDHAKey,
} = require('../utils');

const getCertificateInfo = certificate => {
    const subjectCert = new X509();
    subjectCert.readCertPEM(certificate);

    const subjectString = subjectCert.getSubjectString();
    const subjectParts = subjectString.slice(1).split('/');

    const subject = {};
    for (const field of subjectParts) {
        const kv = field.split('=');
        subject[kv[0]] = kv[1];
    }

    const version = subjectCert.version;
    const basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

    return {
        subject,
        version,
        basicConstraintsCA,
    };
};

const parseAttestationData = buffer => {
    const rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    const flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    const flagsInt = flagsBuf[0];
    const flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt,
    };

    const counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    const counter = counterBuf.readUInt32BE(0);

    let aaguid;
    let credID;
    let COSEPublicKey;

    if (flags.at) {
        aaguid = buffer.slice(0, 16);
        buffer = buffer.slice(16);
        const credIDLenBuf = buffer.slice(0, 2);
        buffer = buffer.slice(2);
        const credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen);
        buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return {
        rpIdHash,
        flagsBuf,
        flags,
        counter,
        counterBuf,
        aaguid,
        credID,
        COSEPublicKey,
    };
};

exports.parseFidoPackedKey = (authenticatorKey, clientDataJSON) => {
    const authenticatorData = parseAttestationData(authenticatorKey.authData);

    const clientDataHash = hash(
        'sha256',
        Buffer.from(clientDataJSON, 'base64')
    );
    const signatureBaseBuffer = Buffer.concat([
        authenticatorKey.authData,
        clientDataHash,
    ]);

    const signatureBuffer = authenticatorKey.attStmt.sig;
    let publicKey;

    if (authenticatorKey.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */
        publicKey = verifyFullAttestation(
            authenticatorKey,
            signatureBaseBuffer,
            signatureBuffer
        );
    } else if (authenticatorKey.attStmt.ecdaaKeyId) {
        throw new Error('ECDAA is not supported yet!');
    } else {
        publicKey = verifySurrogateAttestation(
            authenticatorKey,
            signatureBaseBuffer,
            signatureBuffer
        );
    }

    if (!publicKey) {
        return undefined;
    }

    return {
        fmt: 'packed',
        publicKey: publicKey.toString('base64'),
        counter: authenticatorData.counter,
        credID: base64url.fromBase64 (authenticatorData.credID.toString('base64')),
    };
};

exports.validateFidoPackedKey = (
    authenticatorDataBuffer,
    key,
    clientDataJSON,
    base64Signature
) => {
    const authenticatorData = parseAttestationData(authenticatorDataBuffer);

    // tslint:disable-next-line
    if (!(authenticatorData.flags.up)) {
        throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(
        'SHA256',
        Buffer.from(clientDataJSON, 'base64')
    );
    const signatureBaseBuffer = Buffer.concat([
        authenticatorDataBuffer,
        clientDataHash,
    ]);

    const publicKey = convertASN1toPEM(Buffer.from(key.publicKey, 'base64'));
    const signatureBuffer = Buffer.from(base64Signature, 'base64');

    return createVerify('sha256')
        .update(signatureBaseBuffer)
        .verify(publicKey, signatureBuffer);
};

let COSEKEYS = {
    'kty' : 1,
    'alg' : 3,
    'crv' : -1,
    'x'   : -2,
    'y'   : -3,
    'n'   : -1,
    'e'   : -2
}

let COSEKTY = {
    'OKP': 1,
    'EC2': 2,
    'RSA': 3
}

let COSERSASCHEME = {
    '-3': 'pss-sha256',
    '-39': 'pss-sha512',
    '-38': 'pss-sha384',
    '-65535': 'pkcs1-sha1',
    '-257': 'pkcs1-sha256',
    '-258': 'pkcs1-sha384',
    '-259': 'pkcs1-sha512'
}

var COSECRV = {
    '1': 'p256',
    '2': 'p384',
    '3': 'p521'
}

var COSEALGHASH = {
    '-257': 'sha256',
    '-258': 'sha384',
    '-259': 'sha512',
    '-65535': 'sha1',
    '-39': 'sha512',
    '-38': 'sha384',
    '-37': 'sha256',
    '-260': 'sha256',
    '-261': 'sha512',
    '-7': 'sha256',
    '-36': 'sha512'
}



const verifySurrogateAttestation = (
    authenticatorData,
    signatureBaseBuffer,
    signatureBuffer
) => {
    let authDataStruct = parseAttestationData(authenticatorData.authData);
    let signatureIsValid = false;
    let publicKey = null;

    let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
    let hashAlg    = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
    if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
        let x = pubKeyCose.get(COSEKEYS.x);
        let y = pubKeyCose.get(COSEKEYS.y);
        
        let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

        let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

        let ec  = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
        let key = ec.keyFromPublic(ansiKey);

        signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
        if (signatureIsValid) {
            const hexKey = key.getPublic().encode('hex');
            publicKey = Buffer.from(hexKey, 'hex').toString('base64');
        }
    } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
        let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

        let key = new NodeRSA(undefined, { signingScheme });
        key.importKey({
            n: pubKeyCose.get(COSEKEYS.n),
            e: 65537,
        }, 'components-public');

        signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer);
        if (signatureIsValid) {
            publicKey = pemToBase64(key.exportKey('pkcs8-public'));
        }
    } else if(pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
        let x = pubKeyCose.get(COSEKEYS.x);
        let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

        let key = new elliptic.eddsa('ed25519');
        key.keyFromPublic(x)

        signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
        if (signatureIsValid) {
            const hexKey = key.getPublic().encode('hex');
            publicKey = Buffer.from(hexKey, 'hex').toString('base64');
        }
    }

    if(signatureIsValid) {
        return publicKey;
    }

    return undefined;
}

const verifyFullAttestation = (
    authenticatorKey,
    signatureBaseBuffer,
    signatureBuffer
) => {
    const authenticatorData = parseAttestationData(authenticatorKey.authData);

    const publicKey = convertCOSEPublicKeyToRawPKCSECDHAKey(
        authenticatorData.COSEPublicKey
    );
    const leafCert = convertASN1toPEM(authenticatorKey.attStmt.x5c[0]);
    const certInfo = getCertificateInfo(leafCert);
    if (certInfo.subject.OU !== 'Authenticator Attestation') {
        throw new Error(
            'Batch certificate OU MUST be set strictly to "Authenticator Attestation"!'
        );
    }
    if (!certInfo.subject.CN) {
        throw new Error('Batch certificate CN MUST no be empty!');
    }
    if (!certInfo.subject.O) {
        throw new Error('Batch certificate CN MUST no be empty!');
    }
    if (!certInfo.subject.C || certInfo.subject.C.length !== 2) {
        throw new Error(
            'Batch certificate C MUST be set to two character ISO 3166 code!'
        );
    }
    if (certInfo.basicConstraintsCA) {
        throw new Error(
            'Batch certificate basic constraints CA MUST be false!'
        );
    }
    if (certInfo.version !== 3) {
        throw new Error('Batch certificate version MUST be 3(ASN1 2)!');
    }
    const signatureIsValid = createVerify('sha256')
        .update(signatureBaseBuffer)
        .verify(leafCert, signatureBuffer);

    if (signatureIsValid) {
        return publicKey;
    }

    return undefined;
}
