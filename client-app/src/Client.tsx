import React, { DOMElement, useEffect, useRef, useState } from "react";
import "./App.css";
import QRCode from "qrcode";

import jose from "node-jose";
import base64url from "base64url";
import qs from "qs";
import {
  AccessTokenDbRecord,
  AccessTokenId,
  ClientDbRecord,
  ClientId,
  QrCreationResponseBody,
  QrDbRecord,
  QrId,
  ResourceAccessRights,
  TokenResponseBody,
} from "./types";

let jtiStart = new Date().getTime();

const jtiGenerator = () => "" + jtiStart++;

const clientsPersisted = JSON.parse(window.localStorage.clients || "{}");
const claimQr = async (qrPayload: QrCreationResponseBody) => {
  const discoveryUrl = `${qrPayload.oauth.url}/.well-known/smart-configuration`;

  let clientKey, discovery, client;

  if (clientsPersisted[qrPayload.oauth.token]) {
    const rehydrated = clientsPersisted[qrPayload.oauth.token];
    clientKey = await jose.JWK.asKey(rehydrated.key);
    discovery = rehydrated.discovery;
    client = rehydrated.client;
    console.log("Reuse key perissited/");
  } else {
    clientKey = await jose.JWK.createKey("EC", "P-256", {
      alg: "ES256",
      use: "sig",
    });

    let pin = qrPayload.flags?.match("P") ? window.prompt("PIN") : undefined;

    discovery = await fetch(discoveryUrl).then((r) => r.json());
    client = await fetch(discovery.registration_endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${qrPayload.oauth.token}`,
        // only if `P` is included in the flags
        "Shclinks-Pin": pin,
        "Content-Type": "application/json",
        Accept: "application/json",
      } as any,
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

    clientsPersisted[qrPayload.oauth.token] = {
      key: clientKey.toJSON(true),
      discovery,
      client,
    };
    window.localStorage.clients = JSON.stringify(clientsPersisted);
  }


  const assertion = await jose.JWS.createSign({ format: "compact" }, clientKey)
    .update(
      JSON.stringify({
        iss: client.client_id,
        fake: true,
        sub: client.client_id,
        aud: discovery.token_endpoint,
        // no more than 5min in future
        exp: Math.floor(new Date().getTime() / 1000 + 60),
        jti: jtiGenerator(),
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
  return allFiles;
};

function App() {
  const [files, setFiles] = useState<string[]>([]);
  const shclink = window.location.hash.split("shclink:/")[1];
  const qrPayload = JSON.parse(base64url.decode(shclink));
  useEffect(() => {
    claimQr(qrPayload).then((allFiles) => setFiles(allFiles));
  }, []);

  console.log("SC", shclink);
  return (
    <div className="App">
      <header className="App-header">QR Links Demo Client</header>
      <ul>
        {files.map((f, i) => (
          <li>
            <h3>File {i}</h3>
            <pre>{JSON.stringify(f, null, 2)}</pre>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
