import React, { DOMElement, useEffect, useRef, useState } from "react";
import "./App.css";
import QRCode from "qrcode";

import jose from "node-jose";
import base64url from "base64url";

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

let clientKey;
async function startup() {
  clientKey = await jose.JWK.createKey("EC", "P-256", {
    alg: "ES256",
    use: "sig",
  });
  console.log("Created client key", clientKey.toJSON(false));
}

const PUBLIC_URL = "http://localhost:3000";
const SERVER = "http://localhost:3001";
startup();

const qr = (s: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    QRCode.toDataURL(s, {errorCorrectionLevel: 'M'}, function (err: any, url: string) {
      if (err) return reject(err);
      return resolve(url);
    });
  });
};

interface UiState {
  pin: string,
  policies: {name: string, rar: ResourceAccessRights, selected: boolean}[],
  submissions: number
};

interface ServerState {
  qr: Record<QrId, QrDbRecord>;
  client: Record<ClientId, ClientDbRecord>;
  accessToken: Record<AccessTokenId, AccessTokenDbRecord>;
}

interface DerivedState {
  qrDataUrl: Record<QrId, string>;
}

const toQrPayload = (v: QrDbRecord) => {
  const qrJson = JSON.stringify(v.originalResponse);
  const qrEncoded = base64url.encode(qrJson);
  const qrPrefixed = "shclink:/" + qrEncoded;
  const qr = PUBLIC_URL + "/client#" + qrPrefixed;
  return qr;
};

const defaultUiState: UiState = {
  submissions: 0,
  pin: "",
  policies: [{
    name: "My COVID-19 Immunization Card",
    rar: {
      type: "shclink-view",
      locations: [ `${SERVER}/files/static/example.smart-health-card`],
    },
    selected: false
  }, {
    name: "MyChart Current Immunization Bundle",
    rar: {
      type: "shclink-view",
      locations: [ `${SERVER}/files/proxied/${base64url.encode(`Immunization?patient={{patient}}`)}`],
    },
    selected: false
  }, {
    name: "MyChart Name and Contact Info",
    rar: {
      type: "shclink-view",
      locations: [ `${SERVER}/files/proxied/${base64url.encode(`Patient/{{patient}}`)}`],
    },
    selected: true
  }]
}

function App() {
  const imgRef = useRef<HTMLCanvasElement>(null);

  const qrText = "tesweiopfjk weoifj weoijf ting";
  const [derivedState, setDerivedState] = useState<DerivedState>();
  const [appState, setAppState] = useState<ServerState>();
  const [uiState, setUiState] = useState<UiState>(defaultUiState);

  useEffect(() => {
    console.log("New submission!")
    fetch(SERVER+"/debug.json")
      .then((r) => r.json())
      .then((r) => {
        const ret: ServerState = r;
        console.log("ew as", ret);
        setAppState(ret);
      });
  }, [uiState.submissions]);

  useEffect(() => {
        const qrDataUrls: any = Object.entries(appState?.qr || {}).map(async ([k, v]) => [
          k,
          await qr(toQrPayload(v)),
        ]);

        const resolvedQrDataUrls: any = Promise.all(qrDataUrls).then((p: any) =>
          setDerivedState({ qrDataUrl: Object.fromEntries(p) })
        );
  }, [appState?.qr]);

  const createNewQr = async () => {
  const qrCreationRequest: QrCreationRequestBody = {
    needPin: uiState.pin ?? undefined,
    access: uiState.policies.filter(p=>p.selected).map(p => p.rar),
  };

  const qrCreationResponse: QrCreationResponseBody = (await fetch(
    `${SERVER}/qr`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(qrCreationRequest),
    }
  ).then((r) => r.json())) as QrCreationResponseBody;

  setUiState({...uiState, submissions: uiState.submissions+1})


  }

  const togglePolicy = (name: string) => {
    const policy = uiState.policies.find(p => p.name === name)!;
    policy.selected = !policy.selected;
    setUiState({
      ...uiState
    })
  }

  const changePin = (pin: string) => {
    setUiState({
      ...uiState,
      pin
    })
  }

  const deactivateQr = (qrId: string) => {
    fetch(SERVER + `/qr/${qrId}`, {
      method: "DELETE",
    }).then((r) => {
      setUiState({...uiState, submissions: uiState.submissions+1})
    })
  }

  const deactivateClient = (qrId: string) => {

    fetch(SERVER + `/client/${qrId}`, {
      method: "DELETE",
    }).then((r) => {
      setUiState({...uiState, submissions: uiState.submissions+1})
    })
  }


  return (
    <div className="App">
      <header className="App-header">QR Links Demo</header>

      <h1>Create New Sharing QR</h1>
      <ul>
        {uiState.policies.map(p => <li> <input key={p.name} onChange={()=>togglePolicy(p.name)} checked={p.selected} type="checkbox"></input> {p.name}</li>)}
      </ul>
        Assign PIN? <input type="text" value={uiState.pin} onChange={e => changePin(e.target.value)}></input>
        <br></br>
        <button onClick={e => createNewQr()}>Create</button>
        <hr></hr>

      <h2>Active Sharing Links</h2>
      {Object.values(appState?.qr || {}).filter(v => v.active).map((v: QrDbRecord) => (
        <>
          <h3>{v.access.length} files shared (PIN: {v.needPin})</h3>
          <a className="qr-frame" target="_blank" href={toQrPayload(v)}>
            <img className="qr-main" src={derivedState?.qrDataUrl[v.id]} title={toQrPayload(v)}  />
            <img className="qr-logo" src="logo.svg"></img>
          </a>
          <button onClick={() => deactivateQr(v.id)}>Deactivate</button>
        </>
      ))}

      <h2>Active Clients</h2>
      {Object.values(appState?.client || {}).filter(c => c.active).map((v: ClientDbRecord) => (
        <>
          <h3>{v.name}</h3>
          <button onClick={() => deactivateClient(v.id)}>Deactivate</button>
          <pre>{JSON.stringify(v.queryLog, null, 2)}</pre>
        </>
      ))}
    </div>
  );
}

export default App;
