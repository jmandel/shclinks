import base64url from "base64url";
import crypto from "crypto";
import express from "express";
import fetch from "node-fetch";
import { PORT, PUBLIC_URL } from "./config";
import resources from "./resources.json";
import jose from "node-jose";

interface ResourceAccessRights {
  type: "shclink-view";
  locations?: string[];
  actions?: string[];
  datatypes?: string[];
}

interface QrCreationRequestBody {
  needPin?: string;
  claimLimit?: number;
  expireAfter?: number;
  access: ResourceAccessRights[];
}

interface QrCreationResponseBody {
  url: string;
  flags: string;
  exp?: number;
}

interface QRDetails {
  id: string;
  request: QrCreationRequestBody;
  claims: {
    clientName?: string;
    clientSpecificUrl: string;
    queryLog: string[];
    locationAlias: Record<string, string>;
  }[];
}

const randomId = () => base64url.encode(crypto.randomBytes(32));
const app = express();
app.use(express.json());
app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
  e2etest();
});


type QRID = string;
const QRs: Map<QRID, QRDetails> = new Map();

app.post("/qr", async (req, res) => {
  const qrCreationRequest = req.body as QrCreationRequestBody;
  const qrId = randomId();
  QRs.set(qrId, {
    id: qrId,
    request: qrCreationRequest,
    claims: [],
  });
  res.json({
    url: `${PUBLIC_URL}/qr/${qrId}/claim`,
    flags: "L" + (qrCreationRequest.claimLimit ? "O" : "") + (qrCreationRequest.needPin ? "P" : ""),
    exp: qrCreationRequest.expireAfter,
  });
});

app.post("/qr/:id/claim", (req, res) => {
  const pin = req.query.PIN;
  const id = req.params.id;
  const policy = QRs.get(id);

  if (!policy || policy.claims.length >= (policy.request.claimLimit || Infinity)) {
    res.status(403);
    return res.json(`QR ${id} is not valid or has already been claimed`);
  }

  if (policy.request.needPin && policy.request.needPin !== pin) {
    res.status(403);
    return res.json(`Supplied PIN is invalid`);
  }

  const clientSpecificUrl = `/qr/${id}/claimed/${randomId()}`;

  policy.claims.push({
    clientName: (req.query.clientName as string) || "unknown",
    clientSpecificUrl,
    queryLog: [`Claimed: ${new Date()}`],
    locationAlias: Object.fromEntries(
      Array.from(new Set(policy.request.access.flatMap((a) => a.locations || [])).values()).map((l) => [l, randomId()])
    ),
  });

  res.redirect(301, clientSpecificUrl);
});

app.get("/qr/:id/claimed/:cid", (req, res) => {
  const { cid, id } = req.params;
  const policy = QRs.get(id);

  if (!policy) {
    res.status(403);
    return res.json(`QR ${id} is no longer valid`);
  }

  const claimDetails = policy.claims.find((c) => c.clientSpecificUrl === req.url);
  if (!claimDetails) {
    res.status(403);
    return res.json(`This QR has not been correctly claimed.`);
  }

  res.json(
    policy.request.access.map((a) => ({
      ...a,
      locations: a.locations?.map((l) => `${PUBLIC_URL}/qr/${id}/claimed/${cid}/files/${claimDetails.locationAlias[l]}`),
    }))
  );
});

app.get("/qr/:id/claimed/:cid/files/:fileid", async (req, res) => {
  const { cid, id, fileid } = req.params;
  const policy = QRs.get(id)!;
  const claimDetails = policy.claims.find((c) => c.clientSpecificUrl === `/qr/${id}/claimed/${cid}`)!;

  const trueLocation = Object.entries(claimDetails.locationAlias).find(
    ([original, clientSpecific]) => clientSpecific === fileid
  )![0];

  // TODO proxy this in a sane way
  const proxied = await fetch(trueLocation);
  res.status(proxied.status);
  res.header("Content-Type", proxied.headers.get("content-type") || "application/text");
  res.send(await proxied.text());
});

const keyFromPreimage = async (preImage: string) =>
  jose.JWK.asKey({
    alg: "A256GCM",
    kty: "oct",
    k: crypto.createHash("sha256").update(preImage).digest(),
  });

const encrypt = async (payloadMimeType: string, payload: string, keyPreimage: string) =>
  jose.JWE.createEncrypt(
    {
      format: "compact",
      fields: { payloadMimeType },
    },
    await keyFromPreimage(keyPreimage)
  )
    .update(payload)
    .final();

const decrypt = async (payload: string, keyPreimage: string) => {
  const decrypted = await await jose.JWE.createDecrypt(await keyFromPreimage(keyPreimage)).decrypt(payload);
  return {
    payloadMimeType: (decrypted.header as any)["payloadMimeType"],
    payload: decrypted.plaintext,
  };
};

// Fake static file hosting with the magic of dynamic filtering
app.get("/hosted/fake-encryption/:fakeEncryptionKeyPreimage/:file.json", async (req, res) => {
  const fhirFilter = new RegExp(req.params.file.replace(".json", ""), "i");
  const filtered = resources.entry.filter((r) => JSON.stringify(r).match(fhirFilter));
  const filePayload = JSON.stringify({ ...resources, entry: filtered });
  const jwe = await encrypt("application/fhir+json", filePayload, req.params.fakeEncryptionKeyPreimage);

  res.status(200);
  res.header("Content-Type", "application/jose");
  res.send(jwe);
});

export async function e2etest() {
  const fakeEncryptionKey = randomId();

  const qrCreationRequest: QrCreationRequestBody = {
    needPin: "1234",
    access: [
      {
        type: "shclink-view",
        locations: [
          // normally we'd encrypt and upload these. But **for demo purposes**
          // pretend they exist and have 'static' fileserver generate them on the fly
          `${PUBLIC_URL}/hosted/fake-encryption/${fakeEncryptionKey}/vital.json`,
          `${PUBLIC_URL}/hosted/fake-encryption/${fakeEncryptionKey}/glucose.json`,
        ],
        datatypes: ["application/fhir+json"],
      },
    ],
  };

  const qrCreationResponse: QrCreationResponseBody = (await fetch(`${PUBLIC_URL}/qr`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(qrCreationRequest),
  }).then((r) => r.json())) as QrCreationResponseBody;
  console.log("Initialized QR", JSON.stringify(qrCreationResponse, null, 2), qrCreationResponse.url);

  const qrBody = {
    ...qrCreationResponse,
    decrypt: fakeEncryptionKey,
  };
  const qr = `shclink:/` + base64url.encode(JSON.stringify(qrBody));
  console.log(qrBody)
  console.log("QR to scan", qr)
  // --- then in the client, `qr` is the onyl input needed

  const manifest = (await fetch(qrBody.url + "?PIN=1234", {
    method: "POST",
  }).then((r) => r.json())) as ResourceAccessRights[];
  console.log("Got manifest", manifest);

  const fetchOne = (u: string): Promise<string> => fetch(u).then((r) => r.text());
  const allFiles = await Promise.all(
    manifest.flatMap((rar) => rar.locations || []).map((l) => fetchOne(l).then((l) => decrypt(l, qrBody.decrypt)))
  );
  console.log(
    "Got files",
    allFiles.map((f) => [f.payloadMimeType, JSON.parse(f.payload.toString())])
  );
}