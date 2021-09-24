import jose from 'node-jose';
import express from 'express';

import resources from './resources.json';

import base64url from 'base64url';
import crypto, { randomUUID } from 'crypto';

const PORT = parseInt(process.env.PORT || "3000")
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`

import ExpressServeStaticCore from 'express-serve-static-core/index'


type QrLinkPayloadFlag = "L" | "O" | "P" | "";
interface QrLinkPayload {
    gnap: {
        url: string,
        access: string
    },
    exp?: number,
    flags?: `${QrLinkPayloadFlag}${QrLinkPayloadFlag}${QrLinkPayloadFlag}`,
    decrypt?: string
}

interface AccessTokenPayload {
    label: string,
    access: [{
        locations: string[]
    } | string]
}

const app = express()

app.use(express.raw({type: "application/jose"}))


app.get('/', (req, res) => {
  res.json(resources);
})

interface GnapClient {
        class_id?: string,
        display?: {
            name?: string,
            uri?: string
        }
        key: {
            proof: "jws",
            jwk: {
                kty: "EC",
                kid: string,
                use: "sig",
                alg: "ES256"
            }
        }

}
interface GnapTxPayload {
    access_token: {
        access: string[]
    },
    client: GnapClient
}

const clients = {}

const gnapAuthorized: ExpressServeStaticCore.RequestHandler = async (req, res, next) =>  {
    const jwsRaw = req.body as Buffer;

    try {
        const jws = jwsRaw.toString();
        const unverifiedPayload = JSON.parse(base64url.decode(jws.split(".")[1]));
        const newClientKey = await jose.JWK.asKey(unverifiedPayload.client.key);

        const verifiedJws = await jose.JWS.createVerify(newClientKey).verify(jws);
        const verifiedHeader = verifiedJws.header as {htm: string, kid: string, uri: string, ath?: string, created: number}
        const verifiedPayload = JSON.parse(verifiedJws.payload.toString())

        if (verifiedHeader['htm'] !== req.method) {
            throw `Failed htm ${verifiedHeader.htm} vs ${req.method}`
        }

        if (verifiedHeader['uri'] !== `${PUBLIC_URL}${req.url}`) {
            throw `${PUBLIC_URL}${req.url} vs ${verifiedHeader['uri']}`
        }

        if ( Math.abs((new Date().getTime()) / 1000  - verifiedHeader.created) > 300) {
            throw `Authn token created more than 300 seconds away from current time`
        }
        
        //TODO add check for ath when present

        let gnapRequest = req as any;
        gnapRequest.gnap = {
            verified: true,
            body: verifiedPayload
        }

    } catch(e: any) {
        res.json(e.toString());
        next(e);
    }

    next()
}

const registeredQrs: Record<string, GnapRARItem> = {
    'secret-access-value-123': {
        locations: [`${PUBLIC_URL}/data/by-policy/glucose.json`]
    }
}

const validateAccessKey = async(accessKey: string): Promise<GnapRARItem> => {
    if (registeredQrs[accessKey]) {
        return registeredQrs[accessKey]
    }

    throw "Not found"
}

interface GnapAccessToken {
    value: string,
    manage?: string,
    access: GnapRARItem[]
}

const approvedAccessTokens: Record<string, GnapAccessToken> = {

}

const generateAccessToken = async (access: GnapRARItem): Promise<GnapAccessToken> => {

    let value = randomUUID();
    approvedAccessTokens[value] = {
        value,
        access: [access]
    }

    return approvedAccessTokens[value];
}

app.post('/gnap', gnapAuthorized, async (req, res) => {
    console.log("gnap", (req as any).gnap.body);

    try {
        const gnapRequestBody: GnapTxPayload = (req as any).gnap.body;
        const qr = await Promise.all(gnapRequestBody.access_token.access.map(validateAccessKey))
        console.log("QR", qr)
        const tokenResponse = await generateAccessToken(qr[0])
        return res.json({
            access_token: [tokenResponse]
        })
    } catch (e) {
        return res.json(e);
    }


    // TODO verify the claims inside or throw
})

app.get('/data/by-policy/:deets.json', async (req, res) => {
    const policy = new RegExp(req.params['deets'], "i");
    const filtered = resources.entry.filter(r => JSON.stringify(r).match(policy));
    console.log("pp", policy, resources.entry.length, filtered.length)
    res.json({...resources, entry: filtered});
})

app.get('/open/data/by-policy/:deets.json', async (req, res) => {
    const policy = new RegExp(req.params['deets'], "i");
    const filtered = resources.entry.filter(r => JSON.stringify(r).match(policy));
    console.log("pp", policy, resources.entry.length, filtered.length)
    res.json({...resources, entry: filtered});
})


app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`)
})

interface GnapJwsHeaders {
    typ: "gnap-binding+jws",
    htm: string,
    uri: string,
    created: number,
    ath?: string
}
const signJwsAttached = async (key: jose.JWK.Key, method: string, uri: string, payload?: object, accessTokenValue?: string): Promise<string> => {
    const headers: GnapJwsHeaders = {
        typ: "gnap-binding+jws",
        htm: method,
        uri: uri,
        created: Math.floor((new Date().getTime())/1000),
    };

    if (accessTokenValue) {
        headers.ath = base64url.encode(crypto.createHash('sha256').update(accessTokenValue).digest())
    }

    const sig = await jose.JWS.createSign({format: "compact", fields: headers}, key).update(JSON.stringify(payload)).final() as unknown as string;

    return sig
}
 
interface GnapRARItem {
    actions?: ("read")[]
    locations: string[],
    datatypes?: ("application/smart-health-card" | "application/fhir+json")[]
}

interface GnapRegistrationRequest {
    access: GnapRARItem,
    client: GnapClient
}

interface GnapRegistrationResponse {
    resource_reference: string
}

const registerResourceSet = async (filePath: string): Promise<GnapRegistrationResponse> => {
    return {
        resource_reference: `fixme-encrypt-${filePath}`
    }
}

async function prep() {
    // const jwkEncrypt = (await jose.JWK.createKey("EC", "P-256", {"use": "enc", "alg": "ECDH-ES", "enc": "A256GCM"}));
    // console.log("JWK", jwkEncrypt)
    const jwkSign = (await jose.JWK.createKey("EC", "P-256", {"alg": "ES256", "use": "sig"}));
    console.log("JWK", jwkSign)
    // const pinJwe = await jose.JWE.createEncrypt({format: "compact", contentAlg: "A256GCM"}, jwkEncrypt,).update("1234").final();
    // console.log("PIN", pinJwe)
    const sig = await jose.JWS.createSign({format: "compact", fields: {}}, jwkSign).update(JSON.stringify({
        authz: "https://server.example.org/gnap/tx",
        access: "80b60365-1d5a-4001-afbc-a45e3a8415a4", // authz server will infer the issuer based on who registered this
        exp: (new Date().getTime())/1000 + 60*5, // good for five minutes
        flag: "PO"  // PIN required; One-time use
    })).final() as unknown as string;
    console.log("sig", sig, "\n", sig.length)

    const accessTokenRequestPayload: GnapTxPayload = {
        access_token:  {
            access: ["secret-access-value-123"]
        },
        client: {
            key: jwkSign.toJSON(false) as GnapTxPayload['client']['key']
        }
    }

    console.log("gnap tx jws attached", await signJwsAttached(jwkSign, "POST", "http://localhost:3000/gnap", accessTokenRequestPayload))
}

// Register PIN at the same time as registering the resource set, so it doesn't need to flow through the QR

prep()
