import base64url from "base64url";
import crypto, { randomUUID } from "crypto";
import express from "express";
import ExpressServeStaticCore from "express-serve-static-core/index";
import jose from "node-jose";
import { METHODS_WITHOUT_BODY, PORT, PUBLIC_URL } from "./config";
import { e2etest } from "./demo";
import {
  GnapAccessToken,
  GnapAccessTokenResponseSingle,
  GnapClient,
  GnapRARItem,
  GnapRARItemReference,
  GnapTxRequestPayload,
} from "./gnap-lib";
import resources from "./resources.json";
import { QrPolicy, QrPolicy_CreateRequestBody } from "./shclinks-lib";

type SHCPackageAccessPolicy = {
  who: { type: "keyholder"; keyThumbprint: string } | { type: "anyone" };
  package?: string;
  permission: "claim" | "view" | "manage" | "initialize";
};

type PolicyInputs = [
  accessRequest: GnapRARItem<SHCRARItemTypes> | GnapRARItemReference,
  gnapPayload: GnapTxRequestPayload,
  clientAccessFromToken: GnapAccessToken | null
];

type PolicyFunction = (...inputs: PolicyInputs) => Promise<null | {
  grantedAccess: (GnapRARItem<SHCRARItemTypes> | GnapRARItemReference)[];
  enablingPolicies: SHCPackageAccessPolicy[];
}>;

type SHCRARItemTypes = "shclink-read" | "shclink-modify" | "shclink-share";

interface ExpressRequestGnap {
  body: GnapTxRequestPayload | QrPolicy_CreateRequestBody; // TODO figure out how to make this generic
  accessTokenValid: boolean,
  accessFromToken: GnapAccessToken | null;
}

const app = express();

app.use(express.raw({ type: "application/jose" }));

app.get("/", (req, res) => {
  res.json(resources);
});

async function introspect(accessTokenValue: string): Promise<DbAccessTokenRecord & {valid: boolean}> {
  const token = approvedAccessTokens[accessTokenValue];
  return {
    ...token,
    valid: token.expirationTime > new Date().getTime() / 1000
  };
}

const gnapAuthorized: ExpressServeStaticCore.RequestHandler = async (req, res, next) => {
  const jwsRaw = req.body as Buffer;

  try {
    const jws = METHODS_WITHOUT_BODY.includes(req.method) ? (req.headers["detached-jws"] as string) : jwsRaw.toString();

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
      body: verifiedPayload ? JSON.parse(verifiedPayload) : null,
      accessTokenValid: !!accessFromToken?.valid,
      accessFromToken: accessFromToken?.accessToken ?? null,
    };

    next();
  } catch (e: any) {
    res.json(e.toString());
    next(e);
  }
};

const registeredQrs: Record<string, QrPolicy> = { };

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

declare module "express-serve-static-core" {
  export interface Request {
    gnap: ExpressRequestGnap;
  }
}

// TODO Separate out policies from packages, so one package can have >1 QR policy at a time
app.get("/shclinks/:clientId/:packageId/data/:file", gnapAuthorized, async (req, res) => {
  try {
    if (!req.gnap.accessTokenValid) {
      throw "Token is expired"
    }
    if (
      !req.gnap.accessFromToken?.access.some(
        (a) => typeof a === "object" && a.type === "shclink-read" && a.locations.some((l) => l === `${PUBLIC_URL}${req.url}`)
      )
    ) {
      throw `Supplied access token ${JSON.stringify(req.gnap.accessFromToken)} does not provide access to ${req.url}`;
    }

    const fhirFilter = new RegExp(req.params.file.replace(".json", ""), "i");
    const filtered = resources.entry.filter((r) => JSON.stringify(r).match(fhirFilter));
    res.json({ ...resources, entry: filtered });
  } catch (e: any) {
    res.status(500);
    res.json(e.toString());
  }
});

app.put("/shclinks/:clientId/:packageId/policy", gnapAuthorized, async (req, res) => {
  try {
    console.log("Encountered a share request");
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
    console.log("Failed to create share policy", e);
    res.status(500);
    res.json(e.toString());
  }
});

app.post("/gnap", gnapAuthorized, async (req, res) => {
  try {
    const expressRequestGnap = req.gnap;
    const gnapRequestBody = req.gnap.body as GnapTxRequestPayload<SHCRARItemTypes>;
    console.log("Parsed gnap body", JSON.stringify(gnapRequestBody, null, 2));
    const value = randomUUID();

    const combinedPolicy = firstPolicyWins(
      anyoneCanInitializeShcPackage,
      creatorCanManageShcPackage,
      anyoneCanClaimActiveQr
      //previousQrClaimantCanReadUntilDeactivated
    );

    let policyResult = {
      grantedAccess: [] as GnapAccessTokenResponseSingle["access_token"]["access"] ,
      enablingPolicies: [] as SHCPackageAccessPolicy[] 
    }
    for (let a of gnapRequestBody.access_token.access) {
      const nextPolicyResult = await combinedPolicy(a, gnapRequestBody, expressRequestGnap.accessFromToken);
      if (nextPolicyResult !== null) {
        policyResult = {
          grantedAccess: policyResult.grantedAccess.concat(nextPolicyResult.grantedAccess),
          enablingPolicies: policyResult.enablingPolicies.concat(nextPolicyResult.enablingPolicies)
        }
      }
    }

    const response: GnapAccessTokenResponseSingle = {
      access_token: {
        value,
        access: policyResult.grantedAccess,
      },
    };

    await saveAccessToken(response.access_token, policyResult.enablingPolicies, gnapRequestBody.client);
    res.json(response);
  } catch (e) {
    console.log("ERROR", e);
    res.status(500);
    return res.send(e);
  }
});

app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
  e2etest();
});