import jose from "node-jose";
import { PUBLIC_URL } from "./config";
import { GnapTxRequestPayload, GnapTxResponsePayload, signedFetch } from "./gnap-lib";
import { QrPolicy_CreateRequestBody } from "./shclinks-lib";

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

export async function e2etest() {
  // TODO begin e2e tests in this sequence.
  // * Generate a  Sharer client key
  const sharerKey = await jose.JWK.createKey("EC", "P-256", { alg: "ES256", use: "sig" });

  // * Initialize a package
  const gnapRequest: GnapTxRequestPayload = {
    access_token: { access: ["shclink-initialize"] },
    client: {
      proof: "jws",
      key: { jwk: sharerKey.toJSON(false) as any },
    },
  };

  const initializePackageResponse = (await signedFetch(sharerKey)(`${PUBLIC_URL}/gnap`, {
    method: "POST",
    body: gnapRequest,
  }).then((r) => r.json())) as GnapTxResponsePayload;

  console.log("Initialized package", JSON.stringify(initializePackageResponse, null, 2));

  // * Declare a policy on the package bound to two JSON "files": /glucose.json and /vital.json
  const getLocationForType = (accessResponse: GnapTxResponsePayload, type: string) =>
    accessResponse.access_token.access.filter((a) => a.type === type).flatMap((a) => a.locations)[0];

  const policyLocation = getLocationForType(initializePackageResponse, "shclink-share");
  const dataLocation = getLocationForType(initializePackageResponse, "shclink-modify");

  const createQrPolicyRequest: QrPolicy_CreateRequestBody = {
    claimLimit: 1,
    locations: [`${dataLocation}/glucose.json`, `${dataLocation}/vital-sign.json`],
  };

  const createQrPolicyResponse = await signedFetch(sharerKey, initializePackageResponse.access_token.value)(policyLocation, {
    method: "PUT",
    body: createQrPolicyRequest,
  }).then((r) => r.json());

  console.log("Shared package", JSON.stringify(createQrPolicyResponse, null, 2));

  // * Generate a Receiver client key

  const gnap = createQrPolicyResponse.gnap;
  const receiverKey = await jose.JWK.createKey("EC", "P-256", { alg: "ES256", use: "sig" });

  const claimQrRequest: GnapTxRequestPayload = {
    access_token: {
      access: [gnap.access],
    },
    client: {
      proof: "jws",
      key: { jwk: receiverKey.toJSON(false) as any },
    },
  };

  // * Claim the package (i.e., request an access token)
  const claimQrResponse = (await signedFetch(receiverKey)(gnap.url, {
    method: "POST",
    body: claimQrRequest,
  }).then((r) => r.json())) as GnapTxResponsePayload;

  const receiverAccessToken = claimQrResponse.access_token.value;

  console.log("Claimed QR for package", JSON.stringify(claimQrResponse, null, 2));

  // * Fetch the JSON files inside
  const fetchOneFile = signedFetch(receiverKey, receiverAccessToken);

  const allFiles = await Promise.all(
    claimQrResponse.access_token.access.flatMap((a) => a.locations).map((l) => fetchOneFile(l).then((r) => r.json()))
  );

  console.log(
    "Got all files",
    allFiles.map((b) => "Entries: " + b.entry.length)
  );
}
