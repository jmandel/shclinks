import base64url from "base64url";
import cors from 'cors';
import crypto from "crypto";
import express from "express";
import fetch, { HeaderInit } from "node-fetch";
import jose from "node-jose";
import path from "path";
import qs from "qs";
import {
  DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS,
  MAX_FAILURES_TO_CLAIM_QR,
  PORT,
  PUBLIC_URL
} from "./config";
import headlessWorkflow from "./mychart-proxy/token";
import resources from "./resources.json";


interface ResourceAccessRights {
  type: "shclink-view";
  locations?: string[];
  actions?: string[];
  datatypes?: string[];
}

interface QrCreationRequestBody {
  needPin?: string;
  claimLimit?: number;
  exp?: number;
  access: ResourceAccessRights[];
}

interface QrCreationResponseBody {
  oauth: {
    url: string;
    token: string;
  };
  flags?: string;
  exp?: number;
}

type QrId = string;
interface QrDbRecord extends QrCreationRequestBody {
  id: QrId;
  active: boolean;
  failures: number;
  originalResponse: QrCreationResponseBody;
}

type ClientId = string;
interface ClientDbRecord {
  id: ClientId;
  qr: QrId;
  active: boolean;
  jwk: JwkES256;
  queryLog: {
    when: number;
    what: string;
  }[];
  name?: string;
  contacts?: string[];
}

type AccessTokenId = string;
interface AccessTokenDbRecord {
  id: AccessTokenId;
  client: ClientId;
  exp: number;
}

const QrDb: Map<QrId, QrDbRecord> = new Map();
const ClientDb: Map<ClientId, ClientDbRecord> = new Map();
const AccessTokenDb: Map<AccessTokenId, AccessTokenDbRecord> = new Map();

const randomId = () => base64url.encode(crypto.randomBytes(32));
const publicUrl = (s: string) => `${PUBLIC_URL}${s}`;
const currentEpochSeconds = () => Math.floor(new Date().getTime() / 1000);

const app = express();
app.use(cors())
app.set("json spaces", 2);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
  // e2etest();
});

app.get("/debug.json", async (req, res) => {
  res.json({
    qr: Object.fromEntries(QrDb.entries()),
    client: Object.fromEntries(ClientDb.entries()),
    accessToken: Object.fromEntries(AccessTokenDb.entries()),
  });
});

app.delete("/qr/:id", async (req, res) => {
  const qr = QrDb.get(req.params.id)!;
  qr.active = false;
  res.json(qr)
});

app.delete("/client/:id", async (req, res) => {
  const client = ClientDb.get(req.params.id)!;
  client.active = false;
  res.json(client)
});
  
app.post("/qr", async (req, res) => {
  const qrCreationRequest = req.body as QrCreationRequestBody;
  const id = randomId();

  const qrResponse: QrCreationResponseBody = {
    oauth: {
      url: publicUrl("/oauth"),
      token: id,
    },
    flags:
      "L" +
      (qrCreationRequest.claimLimit ? "O" : "") +
      (qrCreationRequest.needPin ? "P" : ""),
    exp: qrCreationRequest.exp,
  };
 
  QrDb.set(id, {
    ...qrCreationRequest,
    id,
    active: true,
    failures: 0,
    originalResponse: qrResponse
  });

 res.json(qrResponse);
});

app.get("/oauth/.well-known/smart-configuration", (req, res) => {
  res.json({
    registration_endpoint: publicUrl("/oauth/register"),
    token_endpoint: publicUrl("/oauth/token"),
    capabilities: ["shclinks"],
    token_endpoint_auth_methods_supported: ["private_key_jwk"],
  });
});

interface JwkES256 {
  kty: "EC";
  kid: string;
  use: "sig";
  alg: "ES256";
  crv: "P-256";
  x: string;
  y: string;
}
interface ClientRequest {
  token_endpoint_auth_method: "private_key_jwt";
  grant_types: ["client_credentials"];
  jwks: {
    keys: JwkES256[];
  };
  client_name?: string;
  contacts?: string[];
}
app.post("/oauth/register", async (req, res, next) => {
  try {
    const clientRequest = req.body as ClientRequest;
    if (
      clientRequest.token_endpoint_auth_method !== "private_key_jwt" ||
      clientRequest.jwks.keys.length !== 1 ||
      clientRequest.jwks.keys[0].alg !== "ES256" ||
      !clientRequest.grant_types.includes("client_credentials")
    ) {
      // TODO make an error class that returns JSON to client per dynreg
      throw "Invalid registration request. Need exactly one key (ES256), client credentials grant, private_key_jwt auth";
    }

    const authz = req.headers.authorization;
    if (!authz || !authz.match("^[Bb]earer ")) {
      throw "Invalid authorization header. Use `Bearer ${oauth.token}`.";
    }

    const qrId = authz.split("Bearer ")[1];
    const qr = QrDb.get(qrId);
    if (!qr) {
      throw `Invalid authorization token for client registration.`;
    }

    if (!qr.active) {
      throw `Authorization token is from an expired or revoked QR.`;
    }

    const suppliedPin = req.headers["shclinks-pin"];
    if (qr.needPin && qr.needPin !== suppliedPin) {
      qr.failures++;
      if (qr.failures === MAX_FAILURES_TO_CLAIM_QR) {
        qr.active = false;
      }
      throw `PIN required to use this QR. Supplied value of ${suppliedPin} is invalid.`;
    }

    qr.failures = 0; // successful claim resets the count

    const id = randomId();
    ClientDb.set(id, {
      id,
      qr: qrId,
      active: true,
      queryLog: [{ when: new Date().getTime(), what: `Registered` }],
      name: clientRequest.client_name,
      contacts: clientRequest.contacts,
      jwk: clientRequest.jwks.keys[0],
    });
    res.json({
      ...clientRequest,
      client_id: id,
    });
  } catch (e) {
    next(e);
  }
});

interface TokenRequestBody {
  scope?: string;
  grant_type: "client_credentials";
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  client_assertion: string;
}

interface TokenRequestClientAssertionPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  jti: string;
}

interface TokenResponseBody {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  scope: string;
  access: ResourceAccessRights[];
}

app.post("/oauth/token", async (req, res, next) => {
  try {
    const tokenRequest: TokenRequestBody = req.body;
    const clientId = JSON.parse(
      base64url.decode(tokenRequest.client_assertion.split(".")[1])
    ).iss;

    const client = ClientDb.get(clientId)!;
    if (!client.active) {
      throw `Client ${clientId} is no longer active`;
    }

    const clientKey = await jose.JWK.asKey(client?.jwk);
    const verifiedClientAssertion = await jose.JWS.createVerify(
      clientKey
    ).verify(tokenRequest.client_assertion);
    const clientAssertionPayload: TokenRequestClientAssertionPayload =
      JSON.parse(verifiedClientAssertion.payload.toString());
    if (clientAssertionPayload.iss !== clientAssertionPayload.sub) {
      throw "Client assertion iss and sub are not equal";
    }
    if (clientAssertionPayload.aud !== publicUrl("/oauth/token")) {
      throw `Client assertion aud is not ${publicUrl("/oauth/token")}`;
    }

    if (Math.abs(clientAssertionPayload.exp - currentEpochSeconds()) > 180) {
      throw `Client assertion is more than three minutes away from current time`;
    }

    const jtiLog = "Obtained token with JTI " + clientAssertionPayload.jti;
    if (client.queryLog.some((l) => l.what === jtiLog)) {
      throw `Client assertion is reusing a JTI`;
    }

    client.queryLog.push({
      when: new Date().getTime(),
      what: jtiLog,
    });

    const id = randomId();
    const exp = currentEpochSeconds() + DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS;

    AccessTokenDb.set(id, {
      id,
      client: client.id,
      exp,
    });

    const qr = QrDb.get(client.qr)!;
    const tokenResponse: TokenResponseBody = {
      access_token: id,
      token_type: "bearer",
      scope: "__shclinks",
      access: qr?.access,
      expires_in: DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS,
    };
    res.json(tokenResponse);
  } catch (e) {
    next(e);
  }
});

app.use("/files", async (req, res, next) => {
  try {
    const authz = req.headers.authorization?.split("Bearer ")[1]!;
    if (!authz) {
      throw `Need authorization header`;
    }
    const accessToken = AccessTokenDb.get(authz)!;
    if (!accessToken) {
      throw `Invalid access token`;
    }
    const client = ClientDb.get(accessToken.client)!;
    const qr = QrDb.get(client.qr)!;
    if (accessToken?.exp < currentEpochSeconds()) {
      throw `Access token expired at ${accessToken.exp}; it's now ${currentEpochSeconds}`;
    }
    if (
      !qr.access.some((a) =>
        a.locations?.some((l) => l === publicUrl(req.originalUrl))
      )
    ) {
      throw `No access rights support viewing ${publicUrl(
        req.originalUrl
      )}. You only have ${JSON.stringify(qr.access, null, 2)}`;
    }
    next();
  } catch (e) {
    next(e);
  }
});

app.use("/files/static", express.static(path.join(__dirname, "static")));
app.get("/files/proxied/:fileId", async (req, res) => {
  const query = base64url.decode(req.params.fileId);
  const mychartToken = await headlessWorkflow();
  const mychartApiRequest = mychartToken?.fhirBaseUrl + "/" + query.replace("{{patient}}", mychartToken!.patient);
  const result = await fetch(mychartApiRequest, {
    headers: {
      "Authorization": `Bearer ${mychartToken?.access_token}`,
      "Accept": "application/fhir+json"
    }
  }).then(r => r.json());
  res.json(result);
});

app.get("/files/filtered/:fileId", async (req, res) => {
  const fhirFilter = new RegExp(req.params.fileId.replace(".json", ""), "i");
  const filtered = resources.entry.filter((r) =>
    JSON.stringify(r).match(fhirFilter)
  );
  res.json({ ...resources, entry: filtered });
});

export async function e2etest() {
  const qrCreationRequest: QrCreationRequestBody = {
    needPin: "1234",
    access: [
      {
        type: "shclink-view",
        locations: [
          // normally we'd encrypt and upload these. But **for demo purposes**
          // pretend they exist and have 'static' fileserver generate them on the fly
          `${PUBLIC_URL}/files/proxied/${base64url.encode("Patient/{{patient}}")}`,
          // `${PUBLIC_URL}/files/filtered/vital.json`,
          // `${PUBLIC_URL}/files/filtered/glucose.json`,
          // `${PUBLIC_URL}/files/static/example.smart-health-card`,
        ],
        datatypes: ["application/fhir+json"],
      },
    ],
  };

  const qrCreationResponse: QrCreationResponseBody = (await fetch(
    `${PUBLIC_URL}/qr`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(qrCreationRequest),
    }
  ).then((r) => r.json())) as QrCreationResponseBody;

  console.log(
    "Initialized QR",
    JSON.stringify(qrCreationResponse, null, 2),
    qrCreationResponse.oauth.url
  );

  const qrPayload = {
    ...qrCreationResponse,
    // decrypt: fakeEncryptionKey, TODO -- add in support from the redirect prototype
  };

  const qrJson = JSON.stringify(qrPayload);
  const qrEncoded = base64url.encode(qrJson);
  const qrPrefixed = "shclink:/" + qrEncoded;
  const qr = qrPrefixed;

  console.log(qr);
  console.log("QR to scan", qr);

  const discoveryUrl = `${qrPayload.oauth.url}/.well-known/smart-configuration`;
  const discovery = await fetch(discoveryUrl).then((r) => r.json());

  const clientKey = await jose.JWK.createKey("EC", "P-256", {
    alg: "ES256",
    use: "sig",
  });

  const promptReceiverForPin = () => Promise.resolve("1234");
  let pin = qrPayload.flags?.match("P")
    ? await promptReceiverForPin()
    : undefined;

  const client = await fetch(discovery.registration_endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${qrPayload.oauth.token}`,
      // only if `P` is included in the flags
      "Shclinks-Pin": pin,
      "Content-Type": "application/json",
      Accept: "application/json",
    } as HeaderInit,
    body: JSON.stringify({
      token_endpoint_auth_method: "private_key_jwt",
      grant_types: ["client_credentials"],
      jwks: {
        keys: [clientKey.toJSON(false)],
      },
      client_name: "Dr. B's Quick Response Squared", // optional
      contacts: ["drjones@clinic.com"], // optional
    }),
  }).then((r) => r.json());

  console.log("Registered client", client);

  const assertion = await jose.JWS.createSign({ format: "compact" }, clientKey)
    .update(
      JSON.stringify({
        iss: client.client_id,
        fake: true,
        sub: client.client_id,
        aud: discovery.token_endpoint,
        // no more than 5min in future
        exp: Math.floor(new Date().getTime() / 1000 + 60),
        jti: randomId(),
      })
    )
    .final();

  const accessTokenResponse: TokenResponseBody = await fetch(
    discovery.token_endpoint,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: qs.stringify({
        scope: client.scope,
        grant_type: "client_credentials",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      }),
    }
  ).then((r) => r.json());
  console.log(
    "Got Access Token",
    accessTokenResponse.access.flatMap((a) => a.locations)
  );

  const fetchOne = (u: string): Promise<string> =>
    fetch(u, {
      headers: { Authorization: `Bearer ${accessTokenResponse.access_token}` },
    }).then((r) => r.json());

  const allFiles = await Promise.all(
    accessTokenResponse.access
      .flatMap((rar) => rar.locations || [])
      .map((l) => fetchOne(l))
  );
  console.log(allFiles);
}
