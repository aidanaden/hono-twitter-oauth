import { Buffer } from "node:buffer";

import { OAuth1Tokens, authorizeOAuth1, toHeader } from "./oauth1";
import {
  AccessTokenResult,
  RequestTokenArgs,
  RequestTokenResult,
  TBodyMode,
  TRequestBody,
  TRequestQuery,
  UserV1,
} from "./types";
import {
  addQueryParamsToUrl,
  applyRequestParametersToUrl,
  autoDetectBodyType,
  constructBodyParams,
  formatQueryToString,
  mergeQueryAndBodyForOAuth,
} from "./request-params";
function buildURLFromString(url: string) {
  // Add protocol to URL if needed
  if (!url.startsWith("http")) {
    url = "https://" + url;
  }
  // Convert URL to object that will receive all URL modifications
  return new URL(url);
}

const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

export type IWriteAuthHeadersArgs = {
  headers: Record<string, string>;
  bodyInSignature: boolean;
  url: URL;
  method: string;
  query: TRequestQuery;
  body: TRequestBody;
  appConsumerTokens: OAuth1Tokens;
  accessTokens: Partial<OAuth1Tokens>;
};

type GenerateOAuth1RedirectUrlParams = {
  callbackUrl: string;
  appConsumerTokens: OAuth1Tokens;
};

export async function generateOAuth1RedirectUrl(
  { callbackUrl, appConsumerTokens }: GenerateOAuth1RedirectUrlParams,
  { authAccessType, linkMode }: Partial<RequestTokenArgs> = {},
  realIp: string,
) {
  const args = getFormattedRequestArgs({
    url: "https://api.twitter.com/oauth/request_token",
    method: "POST",
    body: {
      oauth_callback: callbackUrl,
      x_auth_access_type: authAccessType,
    },
    appConsumerTokens,
    // No permanent access tokens available since
    // we have not even been authorized yet
    accessTokens: {},
  });
  // RequestParamHelpers.setBodyLengthHeader(args, args.body);
  const res = await fetch(args.url, {
    method: args.method,
    headers: {
      ...args.headers,
      "x-real-ip": realIp,
    },
    body: args.body,
  });
  // Response is a query string (why tf is it not json???) of `RequestTokenResult`
  const body = await res.text();
  const oauthResult = Object.fromEntries(
    new URLSearchParams(body),
  ) as RequestTokenResult;
  console.log({ oauthResult });
  // TODO: re-enable params in future if needed
  // if (forceLogin !== undefined) {
  //   url += `&force_login=${encodeURIComponent(forceLogin)}`;
  // }
  // if (screenName !== undefined) {
  //   url += `&screen_name=${encodeURIComponent(screenName)}`;
  // }
  let url = `https://api.twitter.com/oauth/${linkMode}?oauth_token=${encodeURIComponent(oauthResult.oauth_token)}`;
  return { url, ...oauthResult };
}

type GenerateOAuth1AccessTokensParams = {
  oauthVerifier: string;
  oauthTokens: OAuth1Tokens;
  appConsumerTokens: OAuth1Tokens;
  realIp: string;
};

export async function generateOAuth1AccessTokens({
  oauthVerifier,
  oauthTokens,
  appConsumerTokens,
  realIp,
}: GenerateOAuth1AccessTokensParams) {
  const args = getFormattedRequestArgs({
    url: "https://api.twitter.com/oauth/access_token",
    method: "POST",
    body: {
      oauth_token: oauthTokens.key,
      oauth_token_secret: oauthTokens.secret,
      oauth_verifier: oauthVerifier,
    },
    appConsumerTokens,
    accessTokens: {},
    // No permanent access tokens available since
    // we are generating them with temp tokens
    // (oauth_token + oauth_verifier received from callback)
    // accessTokens: oauthTokens,
  });
  const res = await fetch(args.url, {
    method: args.method,
    headers: {
      ...args.headers,
      "x-real-ip": realIp,
    },
    body: args.body,
  });
  const body = await res.text();
  const oauthResult = Object.fromEntries(
    new URLSearchParams(body),
  ) as AccessTokenResult;
  return oauthResult;
}

export async function getMe({
  appConsumerTokens,
  accessTokens,
}: {
  appConsumerTokens: OAuth1Tokens;
  accessTokens: OAuth1Tokens;
}): Promise<UserV1> {
  // Exclude unnecessary infos (entities, status)
  // @see https://developer.x.com/en/docs/twitter-api/v1/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
  const args = getFormattedRequestArgs({
    url: "https://api.twitter.com/1.1/account/verify_credentials.json?include_entities=false&skip_status=true",
    method: "GET",
    appConsumerTokens,
    accessTokens,
  });
  const res = await fetch(args.url, {
    method: args.method,
    headers: args.headers,
    body: args.body,
  });
  const user: UserV1 = await res.json();
  return user;
}

export type RawRequestArgs = {
  url: string;
  method: string;
  query?: TRequestQuery;
  appConsumerTokens: OAuth1Tokens;
  accessTokens: Partial<OAuth1Tokens>;
  /** The URL parameters, if you specify an endpoint with `:id`, for example. */
  params?: TRequestQuery;
  body?: TRequestBody;
  headers?: Record<string, string>;
  forceBodyMode?: TBodyMode;
  enableAuth?: boolean;
  enableRateLimitSave?: boolean;
  timeout?: number;
};

export type FormattedHttpRequestArgs = {
  rawUrl: string;
  url: URL;
  method: string;
  headers: Record<string, string>;
  body: RequestInit["body"];
};

export function getFormattedRequestArgs({
  url: stringUrl,
  method,
  query: rawQuery = {},
  body: rawBody = {},
  headers,
  forceBodyMode,
  enableAuth,
  params,
  appConsumerTokens,
  accessTokens,
}: RawRequestArgs): FormattedHttpRequestArgs {
  let body: RequestInit["body"] = undefined;
  method = method.toUpperCase();
  headers = headers ?? {};

  // Add user agent header (Twitter recommends it)
  if (!headers["x-user-agent"]) {
    headers["x-user-agent"] = "cloudflare-worker.twitter-api-v2";
  }

  const url = buildURLFromString(stringUrl);
  // URL without query string to save as endpoint name
  const rawUrl = url.origin + url.pathname;

  // Apply URL parameters
  if (params) {
    applyRequestParametersToUrl(url, params);
  }

  // Build a URL without anything in QS, and QSP in query
  const query = formatQueryToString(rawQuery);

  for (const [param, value] of url.searchParams) {
    query[param] = value;
  }
  // Remove the query string
  url.search = "";

  // Delete undefined parameters
  if (!(rawBody instanceof Buffer)) {
    for (const parameter in rawBody) {
      if (rawBody[parameter] === undefined) delete rawBody[parameter];
    }
  }

  // OAuth signature should not include parameters when using multipart.
  const bodyType = forceBodyMode ?? autoDetectBodyType(url);

  // If undefined or true, enable auth by headers
  if (enableAuth !== false) {
    // OAuth needs body signature only if body is URL encoded.
    const bodyInSignature = BODY_METHODS.has(method) && bodyType === "url";
    headers = writeOauthHeaders({
      headers,
      bodyInSignature,
      method,
      query,
      url,
      body: rawBody,
      appConsumerTokens,
      accessTokens,
    });
  }

  if (BODY_METHODS.has(method)) {
    body = constructBodyParams(rawBody, headers, bodyType) ?? undefined;
  }

  addQueryParamsToUrl(url, query);

  return {
    rawUrl,
    url,
    method,
    headers,
    body,
  };
}

export function writeOauthHeaders({
  headers,
  bodyInSignature,
  url,
  method,
  query,
  body,
  appConsumerTokens,
  accessTokens,
}: IWriteAuthHeadersArgs) {
  headers = { ...headers };

  // Merge query and body
  const data = bodyInSignature ? mergeQueryAndBodyForOAuth(query, body) : query;

  const auth = authorizeOAuth1(
    {
      url: url.toString(),
      method,
      data,
    },
    appConsumerTokens,
    accessTokens,
  );

  headers = { ...headers, ...toHeader(auth) };

  return headers;
}
