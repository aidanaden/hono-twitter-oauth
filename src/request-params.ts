import { Buffer } from "node:buffer";
import {
  TBodyMode,
  TRequestBody,
  TRequestQuery,
  TRequestStringQuery,
} from "./types";
import { percentEncode } from "./encode";

const FORM_BOUNDARY = generateFormBoundary();

/* Helpers functions that are specific to this class but do not depends on instance */

export const JSON_1_1_ENDPOINTS = new Set([
  "direct_messages/events/new.json",
  "direct_messages/welcome_messages/new.json",
  "direct_messages/welcome_messages/rules/new.json",
  "media/metadata/create.json",
  "collections/entries/curate.json",
]);

export function formatQueryToString(query: TRequestQuery) {
  const formattedQuery: TRequestStringQuery = {};
  for (const prop in query) {
    if (typeof query[prop] === "string") {
      formattedQuery[prop] = query[prop] as string;
    } else if (typeof query[prop] !== "undefined") {
      formattedQuery[prop] = String(query[prop]);
    }
  }
  return formattedQuery;
}

export function autoDetectBodyType(url: URL): TBodyMode {
  if (url.pathname.startsWith("/2/") || url.pathname.startsWith("/labs/2/")) {
    // oauth2 takes url encoded
    if (url.password.startsWith("/2/oauth2")) {
      return "url";
    }
    // Twitter API v2 has JSON-encoded requests for everything else
    return "json";
  }

  if (url.hostname === "upload.twitter.com") {
    if (url.pathname === "/1.1/media/upload.json") {
      return "form-data";
    }
    // json except for media/upload command, that is form-data.
    return "json";
  }

  const endpoint = url.pathname.split("/1.1/", 2)[1];

  if (JSON_1_1_ENDPOINTS.has(endpoint)) {
    return "json";
  }
  return "url";
}

export function addQueryParamsToUrl(url: URL, query: TRequestQuery) {
  const queryEntries = Object.entries(query) as [string, string][];
  if (queryEntries.length === 0) {
    return;
  }
  for (const [key, value] of queryEntries) {
    url.searchParams.set(percentEncode(key), percentEncode(value));
  }
}

export function constructBodyParams(
  body: TRequestBody,
  headers: Record<string, string>,
  mode: TBodyMode,
) {
  if (body instanceof Buffer) {
    return body;
  }

  if (mode === "json") {
    if (!headers["content-type"]) {
      headers["content-type"] = "application/json;charset=UTF-8";
    }
    return JSON.stringify(body);
  } else if (mode === "url") {
    if (!headers["content-type"]) {
      headers["content-type"] =
        "application/x-www-form-urlencoded;charset=UTF-8";
    }

    if (Object.keys(body).length) {
      return new URLSearchParams(body).toString().replace(/\*/g, "%2A"); // URLSearchParams doesnt encode '*', but Twitter wants it encoded.
    }

    return "";
  } else if (mode === "raw") {
    throw new Error(
      "You can only use raw body mode with Buffers. To give a string, use Buffer.from(str).",
    );
  } else {
    const form = new FormData();

    for (const parameter in body) {
      form.append(parameter, body[parameter]);
    }

    if (!headers["content-type"]) {
      const formHeaders = getFormHeaders();
      headers["content-type"] = formHeaders["content-type"];
    }

    return form;
  }
}

export function setBodyLengthHeader(
  options: RequestInit,
  body: string | Buffer,
) {
  options.headers = options.headers ?? {};
  if (typeof body === "string" && typeof options.headers === "object") {
    (options.headers as any)["content-length"] = Buffer.byteLength(body);
  } else {
    (options.headers as any)["content-length"] = body.length;
  }
}

export function isOAuthSerializable(item: any) {
  return !(item instanceof Buffer);
}

export function mergeQueryAndBodyForOAuth(
  query: TRequestQuery,
  body: TRequestBody,
) {
  const parameters: any = {};

  for (const prop in query) {
    parameters[prop] = query[prop];
  }

  if (isOAuthSerializable(body)) {
    for (const prop in body) {
      const bodyProp = (body as any)[prop];
      if (isOAuthSerializable(bodyProp)) {
        parameters[prop] =
          typeof bodyProp === "object" &&
          bodyProp !== null &&
          "toString" in bodyProp
            ? bodyProp.toString()
            : bodyProp;
      }
    }
  }

  return parameters;
}

/**
 * Replace URL parameters available in pathname, like `:id`, with data given in `parameters`:
 * `https://twitter.com/:id.json` + `{ id: '20' }` => `https://twitter.com/20.json`
 */
export function applyRequestParametersToUrl(
  url: URL,
  parameters: TRequestQuery,
) {
  url.pathname = url.pathname.replace(
    /:([A-Z_-]+)/gi,
    (fullMatch, paramName: string) => {
      if (parameters[paramName] !== undefined) {
        return String(parameters[paramName]);
      }
      return fullMatch;
    },
  );

  return url;
}

function getFormHeaders() {
  return {
    "content-type": "multipart/form-data; boundary=" + FORM_BOUNDARY,
  };
}

function generateFormBoundary() {
  // This generates a 50 character boundary similar to those used by Firefox.
  let boundary = "--------------------------";
  for (let i = 0; i < 24; i++) {
    boundary += Math.floor(Math.random() * 10).toString(16);
  }
  return boundary;
}
