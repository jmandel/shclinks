type QrLinkPayloadFlag = "L" | "O" | "P" | "";
interface QrLinkPayload {
  gnap: {
    url: string;
    access: string;
  };
  exp?: number;
  flags?: `${QrLinkPayloadFlag}${QrLinkPayloadFlag}${QrLinkPayloadFlag}`;
  decrypt?: string;
}

type GnapRARItemReference = string;
interface GnapAccessToken {
  value: string;
  manage?: string;
  access: (GnapRARItem | GnapRARItemReference)[];
}

interface GnapAccessTokenResponse {
  access_token: GnapAccessToken | GnapAccessToken[];
}

type GnapAccessTokenResponseSingle = GnapAccessTokenResponse & { access_token: GnapAccessToken };

// TODO refactor policy stores to use this structure
type SHCPackageAccessPolicy = {
  who: { type: "keyholder"; keyThumbprint: string } | { type: "anyone" };
  package?: string;
  permission: "claim" | "view" | "manage" | "initialize";
};

type PolicyInputs = [
  accessRequest: GnapRARItem | GnapRARItemReference,
  gnapPayload: GnapTxRequestPayload,
  clientAccessFromToken: GnapAccessToken | null
];
type PolicyFunction = (...inputs: PolicyInputs) => Promise<null | {
  grantedAccess: (GnapRARItem | GnapRARItemReference)[];
  enablingPolicies: SHCPackageAccessPolicy[];
}>;

type GnapRARItemType = "shclink-read" | "shclink-modify" | "shclink-share";
interface GnapRARItem {
  type: GnapRARItemType;
  actions?: ("GET" | "DELETE" | "POST" | "PUT")[];
  locations: string[];
  datatypes?: ("application/smart-health-card" | "application/fhir+json")[];
}

interface GnapClient {
  class_id?: string;
  display?: {
    name?: string;
    uri?: string;
  };
  proof: "jws";
  key: {
    jwk: {
      kty: "EC";
      kid: string;
      use: "sig";
      alg: "ES256";
    };
  };
}
interface GnapTxRequestPayload {
  access_token: {
    access: GnapAccessToken["access"];
  };
  client: GnapClient;
  shclink?: {
    pin?: string;
  };
}

interface GnapTxResponsePayload {
    access_token: {
      value: string,
      access: {
        type: string,
        locations: string[]
      }[]
    }
  }
interface GnapJwsHeaders {
  typ: "gnap-binding+jws";
  htm: string;
  uri: string;
  created: number;
  ath?: string;
}

interface ExpressRequestGnap {
  verified: boolean;
  body: GnapTxRequestPayload | QrPolicy_CreateRequestBody; // TODO figure out how to make this generic
  accessFromToken: GnapAccessToken | null;
}
interface QrPolicy {
  needPin?: string;
  claimLimit: number;
  claims: {
    active: boolean;
    client: GnapClient;
  }[];
  access: GnapRARItem[];
}

interface QrPolicy_CreateRequestBody {
  needPin?: string;
  claimLimit: number;
  locations: string[];
}

import jose from "node-jose";
import express from "express";
import resources from "./resources.json";
import base64url from "base64url";
import crypto, { randomUUID } from "crypto";
import fetch from "node-fetch";

const PORT = parseInt(process.env.PORT || "3000");
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

import ExpressServeStaticCore from "express-serve-static-core/index";

const app = express();

app.use(express.raw({ type: "application/jose" }));

app.get("/", (req, res) => {
  res.json(resources);
});

async function introspect(accessTokenValue: string): Promise<DbAccessTokenRecord> {
  return approvedAccessTokens[accessTokenValue];
}

const gnapAuthorized: ExpressServeStaticCore.RequestHandler = async (req, res, next) => {
  const jwsRaw = req.body as Buffer;

  try {
    const jws = ["HEAD", "OPTIONS", "GET"].includes(req.method) ? (req.headers["detached-jws"] as string) : jwsRaw.toString();

    if (!jws) {
      throw `No JWS found in body or header to authenticate request`;
    }

    let withAccessToken: string | null = null;
    let accessFromToken = null;
    let client: GnapClient;
    if (req.headers["authorization"]?.startsWith("GNAP ")) {
      withAccessToken = req.headers["authorization"].slice(5);
      accessFromToken = await introspect(withAccessToken);
      client = accessFromToken.boundClient;
    } else {
      const unverifiedPayload = JSON.parse(base64url.decode(jws.split(".")[1]));
      client = unverifiedPayload.client;
    }

    console.log("gnap req", withAccessToken, accessFromToken, client)
    const newClientKey = await jose.JWK.asKey(client.key.jwk);
    const verifiedJws = await jose.JWS.createVerify(newClientKey).verify(jws);
    const verifiedHeader = verifiedJws.header as { htm: string; kid: string; uri: string; ath?: string; created: number };
    const verifiedPayload = verifiedJws.payload.toString();

    if (withAccessToken) {
      const expectedAth = base64url.encode(crypto.createHash("sha256").update(withAccessToken).digest());
      if (verifiedHeader.ath !== expectedAth) {
        throw `Expected ath ${expectedAth} in header but received ${verifiedHeader.ath}`;
      }
    }

    if (verifiedHeader.htm !== req.method) {
      throw `Failed htm ${verifiedHeader.htm} vs ${req.method}`;
    }

    if (verifiedHeader.uri !== `${PUBLIC_URL}${req.url}`) {
      throw `${PUBLIC_URL}${req.url} vs ${verifiedHeader["uri"]}`;
    }

    if (Math.abs(new Date().getTime() / 1000 - verifiedHeader.created) > 300) {
      throw `Signed request created more than 300 seconds away from current time`;
    }

    req.gnap = {
      verified: true,
      body: verifiedPayload ? JSON.parse(verifiedPayload) : null,
      accessFromToken: accessFromToken?.accessToken ?? null,
    };

    next();
  } catch (e: any) {
    res.json(e.toString());
    next(e);
  }
};

const registeredQrs: Record<string, QrPolicy> = {
  "secret-access-value-123": {
    claimLimit: 1,
    claims: [],
    access: [
      {
        type: "shclink-read",
        locations: [`${PUBLIC_URL}/data/by-policy/glucose.json`],
      },
    ],
  },
};

interface DbAccessTokenRecord {
  expirationTime: number; // epoch seconds
  accessToken: GnapAccessToken;
  enablingPolicies: SHCPackageAccessPolicy[];
  boundClient: GnapClient;
}

const approvedAccessTokens: Record<string, DbAccessTokenRecord> = {};
const saveAccessToken = async (
  accessToken: GnapAccessToken,
  enablingPolicies: SHCPackageAccessPolicy[],
  boundClient: GnapClient
): Promise<boolean> => {
  approvedAccessTokens[accessToken.value] = {
    expirationTime: new Date().getTime() / 1000 + 300,
    accessToken: accessToken,
    enablingPolicies: enablingPolicies,
    boundClient,
  };
  return true;
};

const anyoneCanInitializeShcPackage: PolicyFunction = async (accessRequest, gnapPayload, clientAccess) => {
  if (accessRequest === "shclink-initialize") {
    const folderUuid = randomUUID();
    console.log("Anone can", gnapPayload);
    const clientId = gnapPayload.client.key.jwk.kid;
    /*
    registeredQrs[folderUuid] = {
      claimLimit: 3,
      claims: [],
      acccess: {}
    }
    */

    return {
      grantedAccess: [
        {
          type: "shclink-modify",
          actions: ["POST", "GET", "PUT", "DELETE"],
          locations: [`${PUBLIC_URL}/shclinks/${clientId}/${folderUuid}/data`],
        },
        {
          type: "shclink-share",
          actions: ["POST", "GET", "PUT", "DELETE"],
          locations: [`${PUBLIC_URL}/shclinks/${clientId}/${folderUuid}/policy`],
        },
      ],
      enablingPolicies: [
        {
          who: { type: "anyone" },
          permission: "initialize",
        },
      ],
    };
  }
  return null;
};

const creatorCanManageShcPackage: PolicyFunction = async (accessRequest, gnapPayload, clientAcces) => {
  if (typeof accessRequest === "object") {
    if (["shclink-modify", "shclink-share"].includes(accessRequest.type)) {
      const clientId = gnapPayload.client.key.jwk.kid;
      const allowedLocationPrefix = `${PUBLIC_URL}/shclinks/${clientId}/`;
      if (accessRequest.locations.every((l) => l.startsWith(allowedLocationPrefix))) {
        return {
          grantedAccess: [accessRequest],
          enablingPolicies: [
            {
              who: { type: "keyholder", keyThumbprint: clientId },
              permission: "manage",
              package: clientId, // TODO use folders instead of entire clinet spaces
            },
          ],
        };
      }
    }
  }
  return null;
};

const anyoneCanClaimActiveQr: PolicyFunction = async (accessRequest, gnapPayload, clientAcces) => {
  if (typeof accessRequest === "string") {
    let qrPolicy = registeredQrs[accessRequest];
    if (!qrPolicy.needPin || qrPolicy.needPin === gnapPayload?.shclink?.pin) {
      if (qrPolicy.claimLimit > qrPolicy.claims.length) {
        qrPolicy.claims.push({ active: true, client: gnapPayload.client });
        return {
          grantedAccess: qrPolicy.access,
          enablingPolicies: qrPolicy.access.map((p) => ({
            who: { type: "anyone" },
            permission: "claim",
            package: accessRequest,
          })),
        };
      }
    }
  }
  return null;
};

/* Maybe with long access token lifetimes, we don't need to support refreshing (?)
const previousQrClaimantCanReadUntilDeactivated: PolicyFunction = async (accessRequest, gnapPayload, clientAcces) => {
  if (typeof accessRequest === "object") {
    if (accessRequest.type === "shclink-read") {
      const clientIsPreviousClaimant = Object.values(registeredQrs).some(
        (v) =>
          v.access.some((a) => accessRequest.locations.every((l) => a.locations.includes(l))) &&
          v.claims.some((c) => c.active && c.client.key.jwk.kid === gnapPayload.client.key.jwk.kid)
      );
      if (clientIsPreviousClaimant) {
        return [accessRequest];
      }
    }
  }
  return [];
};
*/

function firstPolicyWins(...policies: PolicyFunction[]): PolicyFunction {
  return async (...inputs: PolicyInputs) => {
    for (let p of policies) {
      const results = await p(...inputs);
      if (results?.grantedAccess?.length) {
        return results;
      }
    }
    return null;
  };
}

/*
TODO next steps on resoruce API
addQrPolicy:
  post-condition: new policy: [anonymous, package, 'claim']
  * protected by Gnap access token with the right permissions
  * ensure that all 'read' locations sit within the policy bucket 

*/

declare module "express-serve-static-core" {
  export interface Request {
    gnap: ExpressRequestGnap;
  }
}

// TODO Separate out policies from packages, so one package can have >1 QR policy at a time
app.get("/shclinks/:clientId/:packageId/data/:file", gnapAuthorized, async (req, res) => {
  try {
    if (
      !req.gnap.accessFromToken?.access.some(
        (a) => typeof a === "object" && a.type === "shclink-read" && a.locations.some((l) => l === `${PUBLIC_URL}${req.url}`)
      )
    ) {
      throw `Supplied access token ${JSON.stringify(req.gnap.accessFromToken)} does not provide access to ${req.url}`;
    }

    const fhirFilter = new RegExp(req.params.file.replace(".json", ""), "i");
    const filtered = resources.entry.filter((r) => JSON.stringify(r).match(fhirFilter));
    console.log("pp", fhirFilter, resources.entry.length, filtered.length);
    res.json({ ...resources, entry: filtered });
  } catch (e: any) {
    res.status(500);
    res.json(e.toString());
  }
});

app.put("/shclinks/:clientId/:packageId/policy", gnapAuthorized, async (req, res) => {
  try {
    console.log("Encountered a share request")
    if (
      !req.gnap.accessFromToken?.access.some(
        (a) => typeof a === "object" && a.type === "shclink-share" && a.locations.some((l) => l === `${PUBLIC_URL}${req.url}`)
      )
    ) {
      throw `Supplied access token ${JSON.stringify(req.gnap.accessFromToken)} does not provide access to ${req.url}`;
    }

    const policyRequest = req.gnap.body as QrPolicy_CreateRequestBody;
    const allowedDataLocations = `${PUBLIC_URL}${req.url}`.replace(/\/policy$/, "/data/");
    if (!policyRequest.locations.every((l) => l.startsWith(allowedDataLocations))) {
      throw `requested access to a data location ${policyRequest.locations} outside of managed package ${allowedDataLocations}`;
    }

    console.log("looks like a good request", req.params.packageId, req.gnap)

    registeredQrs[req.params.packageId] = {
      needPin: policyRequest.needPin,
      claimLimit: policyRequest.claimLimit,
      claims: [],
      access: [
        {
          type: "shclink-read",
          locations: policyRequest.locations,
        },
      ],
    };

    // Blow away any access tokens baesd on now-invalid claims
    // TODO: determine access token validity during the introspect
    // stage, as a function of stated policies
    Object.entries(approvedAccessTokens).forEach(([k, v]) => {
      if (v.enablingPolicies.some((p) => p.package === req.params.packageId && p.permission === "claim")) {
        delete approvedAccessTokens[k];
      }
    });

    return res.json({
      status: "PUT new policy",
      gnap: {
        url: `${PUBLIC_URL}/gnap`,
        access: req.params.packageId,
      },
      _internalStateDebugRegistered: registeredQrs[req.params.packageId],
    });
  } catch (e: any) {
    console.log("Failed to create share policy", e)
    res.status(500);
    res.json(e.toString());
  }
});

app.post("/gnap", gnapAuthorized, async (req, res) => {
  try {
    const expressRequestGnap = req.gnap;
    const gnapRequestBody = req.gnap.body as GnapTxRequestPayload;
    console.log("Parsed gnap body", JSON.stringify(gnapRequestBody, null, 2));
    const value = randomUUID();

    console.log("Considering", req.gnap);

    const policy = firstPolicyWins(
      anyoneCanInitializeShcPackage,
      creatorCanManageShcPackage,
      anyoneCanClaimActiveQr
      //previousQrClaimantCanReadUntilDeactivated
    );

    let grantedAccess: GnapAccessTokenResponseSingle["access_token"]["access"] = [];
    let enablingPolicies: SHCPackageAccessPolicy[] = [];
    for (let a of gnapRequestBody.access_token.access) {
      const policyResult = await policy(a, gnapRequestBody, expressRequestGnap.accessFromToken);
      if (policyResult !== null) {
        grantedAccess = grantedAccess.concat(policyResult.grantedAccess);
        enablingPolicies = enablingPolicies.concat(policyResult.enablingPolicies);
      }
    }

    const response: GnapAccessTokenResponseSingle = {
      access_token: {
        value,
        access: grantedAccess,
      },
    };

    console.log("saving access token resonse", response);
    await saveAccessToken(response.access_token, enablingPolicies, gnapRequestBody.client);
    res.json(response);
  } catch (e) {
    console.log("ERROR", e);
    res.status(500);
    return res.send(e);
  }
  // TODO verify the claims inside or throw
});

app.get("/open/data/by-policy/:deets.json", async (req, res) => {
  const policy = new RegExp(req.params["deets"], "i");
  const filtered = resources.entry.filter((r) => JSON.stringify(r).match(policy));
  console.log("pp", policy, resources.entry.length, filtered.length);
  res.json({ ...resources, entry: filtered });
});

app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
});

const signJwsAttached = async (
  key: jose.JWK.Key,
  method: string,
  uri: string,
  payload?: object,
  accessTokenValue?: string
): Promise<string> => {
  const headers: GnapJwsHeaders = {
    typ: "gnap-binding+jws",
    htm: method,
    uri: uri,
    created: Math.floor(new Date().getTime() / 1000),
  };

  if (accessTokenValue) {
    headers.ath = base64url.encode(crypto.createHash("sha256").update(accessTokenValue).digest());
  }

  const sig = (await jose.JWS.createSign({ format: "compact", fields: headers }, key)
    .update(JSON.stringify(payload))
    .final()) as unknown as string;
  return sig;
};

const signedFetch =
  (key: jose.JWK.Key, accessTokenValue?: string) =>
  async (
    url: string,
    {
      method,
      body,
    }: {
      method: string;
      body?: object;
    } = {method: "GET", body: undefined}
  ) => {
    const jws = await signJwsAttached(key, method, url, body, accessTokenValue);

    const authzHeaders: Record<string, string> = {};
    if (accessTokenValue) {
      authzHeaders["Authorization"] = `GNAP ${accessTokenValue}` 
    }

    if (["HEAD", "OPTIONS", "GET"].includes(method)) {
      return (await fetch(url, {
        method,
        headers: {
          "Detached-JWS": jws,
          ...authzHeaders
        },
      })).json();
    }

    return (await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/jose",
          ...authzHeaders
      },
      body: jws,
    })).json();
  };

async function prep() {
  const jwkSign = await jose.JWK.createKey("EC", "P-256", { alg: "ES256", use: "sig" });
  console.log("JWK", jwkSign);

  const accessTokenRequestPayload: GnapTxRequestPayload = {
    access_token: {
      access: ["secret-access-value-123"],
    },
    client: {
      proof: "jws",
      key: jwkSign.toJSON(false) as GnapTxRequestPayload["client"]["key"],
    },
  };

  console.log(
    "gnap tx jws attached",
    await signJwsAttached(jwkSign, "POST", "http://localhost:3000/gnap", accessTokenRequestPayload)
  );
}

// prep();

async function test() {
  // TODO begin e2e tests in this sequence.
  // * Generate a  Sharer client key
  const sharerKey = await jose.JWK.createKey("EC", "P-256", { alg: "ES256", use: "sig" });

  // * Initialize a package
  const gnapRequest: GnapTxRequestPayload = {
    access_token: {
      access: ["shclink-initialize"],
    },
    client: {
      proof: "jws",
      key: {
        jwk: sharerKey.toJSON(false) as any,
      },
    },
  };

  const initializePackageResponse = await signedFetch(sharerKey)(`${PUBLIC_URL}/gnap`, {
    method: "POST",
    body: gnapRequest,
  }) as GnapTxResponsePayload;

  console.log("Initialized package", JSON.stringify(initializePackageResponse, null, 2));

  // * Declare a policy on the package bound to two JSON "files": /glucose.json and /vital.json
  const getLocationForType = (accessResponse: GnapTxResponsePayload, type: string) => accessResponse
      .access_token
      .access
      .filter(a => a.type === type).flatMap(a => a.locations)[0];

  const policyLocation = getLocationForType(initializePackageResponse, 'shclink-share')
  const dataLocation = getLocationForType(initializePackageResponse, 'shclink-modify')

  const createQrPolicyRequest: QrPolicy_CreateRequestBody = {
    claimLimit: 1,
    locations: [`${dataLocation}/glucose.json`, `${dataLocation}/vital-sign.json`]
  };

  const createQrPolicyResponse = await signedFetch(sharerKey, initializePackageResponse.access_token.value)(policyLocation, {
    method: "PUT",
    body: createQrPolicyRequest,
  })

  console.log("Shared package", JSON.stringify(createQrPolicyResponse, null, 2));

  // * Generate a Receiver client key

  const gnap = createQrPolicyResponse.gnap
  const receiverKey = await jose.JWK.createKey("EC", "P-256", { alg: "ES256", use: "sig" });

  const claimQrRequest: GnapTxRequestPayload = {
    access_token: {
      access: [gnap.access],
    },
    client: {
      proof: "jws",
      key: {
        jwk: receiverKey.toJSON(false) as any,
      },
    },
  };

  // * Claim the package (i.e., request an access token)
  const claimQrResponse = await signedFetch(receiverKey)(gnap.url, {
    method: "POST",
    body: claimQrRequest,
  }) as GnapTxResponsePayload;

  const receiverAccessToken = claimQrResponse.access_token.value;

  console.log("Claimed QR for package", JSON.stringify(claimQrResponse, null, 2));

  // * Fetch the JSON files inside
  const fetchOneFile = signedFetch(receiverKey, receiverAccessToken)

  const allFiles = await Promise.all(claimQrResponse
    .access_token
    .access
    .flatMap(a => a.locations)
    .map(async (l) => await fetchOneFile(l)))

  console.log("Got all files", allFiles.map(b => "Entries: " + b.entry.length))

}
test();
