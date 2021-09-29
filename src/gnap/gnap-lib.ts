import jose from "node-jose";
import base64url from "base64url";
import crypto from "crypto";
import fetch from "node-fetch";
import { METHODS_WITHOUT_BODY } from "./config";

export interface GnapTxRequestPayload<T extends string = string> {
  access_token: {
    access: GnapAccessToken<T>["access"];
  };
  client: GnapClient;
  shclink?: {
    pin?: string;
  };
}

export interface GnapTxResponsePayload {
  access_token: {
    value: string;
    access: {
      type: string;
      locations: string[];
    }[];
  };
}

export type GnapRARItemReference = string;
export interface GnapAccessToken<T extends string = string> {
  value: string;
  manage?: string;
  access: (GnapRARItem<T> | GnapRARItemReference)[];
}

export interface GnapAccessTokenResponse {
  access_token: GnapAccessToken | GnapAccessToken[];
}

export type GnapAccessTokenResponseSingle = GnapAccessTokenResponse & { access_token: GnapAccessToken };

export interface GnapRARItem<T extends string> {
  type: T;
  actions?: ("GET" | "DELETE" | "POST" | "PUT")[];
  locations: string[];
  datatypes?: ("application/smart-health-card" | "application/fhir+json")[];
}

export interface GnapClient {
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

interface GnapJwsHeaders {
  typ: "gnap-binding+jws";
  htm: string;
  uri: string;
  created: number;
  ath?: string;
}

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

export const signedFetch =
  (key: jose.JWK.Key, accessTokenValue?: string) =>
  async (
    url: string,
    {
      method,
      body,
    }: {
      method: string;
      body?: object;
    } = { method: "GET", body: undefined }
  ) => {
    const jws = await signJwsAttached(key, method, url, body, accessTokenValue);

    const authzHeaders: Record<string, string> = {};
    if (accessTokenValue) {
      authzHeaders["Authorization"] = `GNAP ${accessTokenValue}`;
    }

    let fetchArgs;
    if (METHODS_WITHOUT_BODY.includes(method)) {
      fetchArgs = {
        method,
        headers: {
          "Detached-JWS": jws,
          ...authzHeaders,
        },
      };
    } else {
      fetchArgs = {
        method,
        headers: {
          "Content-Type": "application/jose",
          ...authzHeaders,
        },
        body: jws,
      };
    }

    return fetch(url, fetchArgs);
  };
