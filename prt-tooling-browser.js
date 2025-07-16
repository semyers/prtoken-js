const PRT_SIZE = 79;
const PRT_POINT_SIZE = 33;
const EPOCH_ID_SIZE = 8;
const BITS_PER_BYTE = 8;

class ProbabilisticRevealToken {
    constructor(version, u, e, epoch_id, prt_header, epoch_id_base64) {
        this.version = version;
        this.u = u;
        this.e = e;
        this.epoch_id = epoch_id;
        this.prt_header = prt_header;
        this.epoch_id_base64 = epoch_id_base64;
    }
}

class DecryptionResult {
    constructor(plaintext, hmac_secret) {
        this.plaintext = plaintext;
        this.hmac_secret = hmac_secret;
    }
}

class PlaintextToken {
    constructor(version, ordinal, signal, hmac_valid) {
        this.version = version;
        this.ordinal = ordinal;
        this.signal = signal;
        this.hmac_valid = hmac_valid;
    }
}

function deserializePrt(serializedPrt) {
    if (serializedPrt.byteLength !== PRT_SIZE) {
        console.error(`Invalid PRT size: ${serializedPrt.byteLength}, expected: ${PRT_SIZE}`);
        return null;
    }

    try {
        const dataView = new DataView(serializedPrt);
        let offset = 0;

        const version = dataView.getUint8(offset);
        offset += 1;

        const uSize = dataView.getUint16(offset, false); // Big Endian
        offset += 2;
        if (uSize !== PRT_POINT_SIZE) {
            console.error(`Invalid u_size: ${uSize}, expected: ${PRT_POINT_SIZE}`);
            return null;
        }

        const u = new Uint8Array(serializedPrt, offset, uSize);
        offset += uSize;

        const eSize = dataView.getUint16(offset, false); // Big Endian
        offset += 2;
        if (eSize !== PRT_POINT_SIZE) {
            console.error(`Invalid e_size: ${eSize}, expected: ${PRT_POINT_SIZE}`);
            return null;
        }

        const e = new Uint8Array(serializedPrt, offset, eSize);
        offset += eSize;

        const epochId = new Uint8Array(serializedPrt, offset, EPOCH_ID_SIZE);

        return new ProbabilisticRevealToken(version, u, e, epochId, "", "");
    } catch (ex) {
        console.error(`Failed to deserialize PRT: ${ex}`);
        return null;
    }
}

function getTokenFromHeaderString(prtHeader) {
    try {
        if (prtHeader.startsWith(":")) {
            prtHeader = prtHeader.substring(1);
        }
        if (prtHeader.endsWith(":")) {
            prtHeader = prtHeader.slice(0, -1);
        }

        const prtBytes = Uint8Array.from(atob(prtHeader), c => c.charCodeAt(0));
        const prt = deserializePrt(prtBytes.buffer);
        if (!prt) {
            return null;
        }

        prt.prt_header = prtHeader;
        prt.epoch_id_base64 = btoa(String.fromCharCode.apply(null, prt.epoch_id)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        return prt;
    } catch (ex) {
        console.error(`Failed to get token from header string: ${ex}`);
        return null;
    }
}

function recoverXFromPaddedPoint(point, numPaddingBits) {
    const x_bn = point.getX();
    return x_bn.shrn(numPaddingBits);
}

async function decryptTokenHeader(prtHeader) {
    const prt = getTokenFromHeaderString(prtHeader);
    if (!prt) {
        console.error("Failed to parse token header");
        return null;
    }

    try {
        const keyFile = prt.epoch_id_base64 + ".json";
        const url = `https://raw.githubusercontent.com/explainers-by-googlers/prtoken-reference/main/published_keys/${keyFile}`;

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch key file: ${response.statusText}`);
        }
        const keyData = await response.json();

        const ec = new window.elliptic.ec('p256');

        const d_b64 = keyData.eg.d;
        const d_hex = atob(d_b64.replace(/_/g, '/').replace(/-/g, '+')).split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        const key = ec.keyFromPrivate(d_hex, 'hex');
        const d_bn = key.getPrivate();

        const hmac_secret_b64 = keyData.hmac.k;
        const hmac_secret = Uint8Array.from(atob(hmac_secret_b64.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));

        const pointU = ec.curve.decodePoint(Array.from(prt.u).map(b => b.toString(16).padStart(2, '0')).join(''), 'hex');
        const pointE = ec.curve.decodePoint(Array.from(prt.e).map(b => b.toString(16).padStart(2, '0')).join(''), 'hex');

        const xu = pointU.mul(d_bn);
        const decryptedPoint = pointE.add(xu.neg());

        const xRecovered_bn = recoverXFromPaddedPoint(decryptedPoint, 3 * BITS_PER_BYTE);
        
        const plaintext = new Uint8Array(xRecovered_bn.toArray('be'));

        return new DecryptionResult(plaintext, hmac_secret);
    } catch (e) {
        console.error(`Error: ${e}`);
        return null;
    }
}

async function getPlaintextToken(result) {
    const { plaintext, hmac_secret } = result;

    if (plaintext.length < 26) {
        console.error(`Cannot parse plaintext, buffer too small. Length: ${plaintext.length}`);
        return null;
    }

    try {
        const version = plaintext[0];
        const t_ord = plaintext[1];
        const signal = plaintext.slice(2, 18);
        const received_hmac = plaintext.slice(18, 26);

        const hmacValid = await verifyHmac(version, t_ord, signal, received_hmac, hmac_secret);
        return new PlaintextToken(version, t_ord, signal, hmacValid);
    } catch (e) {
        console.error("Cannot parse plaintext.", e);
        return null;
    }
}

async function verifyHmac(version, t_ord, signal, receivedHmac, hmacSecret) {
    try {
        const key = await crypto.subtle.importKey(
            'raw',
            hmacSecret,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const data = new Uint8Array([version, t_ord, ...signal]);
        
        const signature = await crypto.subtle.sign('HMAC', key, data);
        const truncatedSignature = new Uint8Array(signature, 0, 8);

        // Constant-time comparison is not strictly necessary here, but good practice
        if (receivedHmac.length !== truncatedSignature.length) {
            return false;
        }
        for (let i = 0; i < receivedHmac.length; i++) {
            if (receivedHmac[i] !== truncatedSignature[i]) {
                return false;
            }
        }
        return true;
    } catch (e) {
        console.error(`Error during HMAC verification: ${e}`);
        return false;
    }
}