import { chromium } from "playwright";
import fetch from "node-fetch";
import qs from "qs";
import fs from "fs";
import path from "path";

const MYCHART_USERNAME = process.env.MYCHART_USERNAME!;
const MYCHART_PASSWORD = process.env.MYCHART_PASSWORD!;
const MYCHART_AUTHZ_ENDPOINT = process.env.MYCHART_AUTHZ_ENDPOINT!;
const MYCHART_TOKEN_ENDPOINT = process.env.MYCHART_TOKEN_ENDPOINT!;
const MYCHART_FHIR = process.env.MYCHART_FHIR!;
const MYCHART_REDIRECT_URI = process.env.MYCHART_REDIRECT_URI!;
const MYCHART_CLIENT_ID = process.env.MYCHART_CLIENT_ID!;


interface AccessTokenResponseCache {
  expires: number;
  inflight?: Promise<AccessTokenResponseCache["response"]>;
  response?: { access_token: string; patient: string, expires_in: number; fhirBaseUrl: string; };
}

const CACHE_PATH = path.join(__dirname, "cache.json")
const persist = () => {
    fs.writeFileSync(CACHE_PATH, JSON.stringify(cachedTokenResponse) )
}

let cachedTokenResponse: AccessTokenResponseCache = {
expires: new Date().getTime() / 1000 - 3600
};

try {
    cachedTokenResponse = JSON.parse(fs.readFileSync(CACHE_PATH).toString())
} catch (e){
    console.log("No cached access token response")
}

export const getAuthorizationCode = async () => {
  const browser = await chromium.launch({headless: true}); // Or 'firefox' or 'webkit'.
  const page = await browser.newPage();

  console.log("Authz", MYCHART_AUTHZ_ENDPOINT)
  await page.goto(
    MYCHART_AUTHZ_ENDPOINT + "?" +
      qs.stringify({
        client_id: MYCHART_CLIENT_ID,
        state: "bad",
        scope: "launch",
        redirect_uri: MYCHART_REDIRECT_URI,
        response_type: "code",
        aud: MYCHART_FHIR,
      })
  );

  await page.fill('input[name="Login"]', MYCHART_USERNAME);
  await page.fill('input[name="Password"]', MYCHART_PASSWORD);
  await page.click("text=sign in");
  await page.click("text=continue");
  await Promise.any([page.click("text=continue"), page.click("text=allow access")])

  await page.waitForNavigation(/redirect\.html/ as any);
  const url = await page.url();
  await browser.close();
  const code = new URL(url).searchParams.get("code")!;
  return code;
};

const getAccesToken = async (
  code: string
): Promise<AccessTokenResponseCache["response"]> => {
  return fetch(MYCHART_TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: qs.stringify({
      grant_type: "authorization_code",
      code,
      client_id: MYCHART_CLIENT_ID,
      redirect_uri: MYCHART_REDIRECT_URI,
    }),
  }).then((t) => t.json());
};

export default async function headlessWorkflow(force = false) {

  if (cachedTokenResponse.inflight) {
    console.log("awaiting inflight token")
    return cachedTokenResponse.inflight;
  }

  if (cachedTokenResponse.expires > new Date().getTime() / 1000 && !force) {
    console.log("Returning cached response")
    return cachedTokenResponse.response;
  }

  let newCacheEntryResolve: any, newCacheEntryReject: any;
  const newCacheEntry: AccessTokenResponseCache = (cachedTokenResponse = {
    expires: 0,
    inflight: new Promise((resolve, reject) => {
      newCacheEntryResolve = resolve;
      newCacheEntryReject = reject;
    }),
  });

  try {
    const code = await getAuthorizationCode();
    const tokenResponse: AccessTokenResponseCache["response"] = {
        ...(await getAccesToken(code))!,
        fhirBaseUrl: MYCHART_FHIR
    };
    if (!tokenResponse.access_token) {
        throw "Bad access token response"
    }
    newCacheEntry.response = tokenResponse;
    newCacheEntry.expires = new Date().getTime() / 1000  + tokenResponse.expires_in * .5;
    newCacheEntryResolve(tokenResponse);
    return tokenResponse;
  } catch (e) {
    console.log("errord out on token", e);
    newCacheEntryReject(e);
    throw e;
  } finally {
    delete newCacheEntry.inflight;
    persist()
  }
}

console.log("Load headless")
headlessWorkflow().then(r => console.log("Initial cache", r))