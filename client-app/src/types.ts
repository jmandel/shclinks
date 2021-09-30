export interface JwkES256 {
  kty: "EC";
  kid: string;
  use: "sig";
  alg: "ES256";
  crv: "P-256";
  x: string;
  y: string;
}

export interface ClientRequest {
  token_endpoint_auth_method: "private_key_jwt";
  grant_types: ["client_credentials"];
  jwks: {
    keys: JwkES256[];
  };
  client_name?: string;
  contacts?: string[];
}

export interface ResourceAccessRights {
  type: "shclink-view";
  locations?: string[];
  actions?: string[];
  datatypes?: string[];
}

export interface QrCreationRequestBody {
  needPin?: string;
  claimLimit?: number;
  exp?: number;
  access: ResourceAccessRights[];
}

export interface QrCreationResponseBody {
  oauth: {
    url: string;
    token: string;
  };
  flags?: string;
  exp?: number;
}

export type QrId = string;
export interface QrDbRecord extends QrCreationRequestBody {
  id: QrId;
  active: boolean;
  failures: number;
  originalResponse: QrCreationResponseBody;
}

export type ClientId = string;
export interface ClientDbRecord {
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

export type AccessTokenId = string;
export interface AccessTokenDbRecord {
  id: AccessTokenId;
  client: ClientId;
  exp: number;
}

export interface TokenResponseBody {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  scope: string;
  access: ResourceAccessRights[];
}

