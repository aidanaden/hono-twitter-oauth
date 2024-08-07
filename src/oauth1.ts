import { createHmac } from "node:crypto";
import { percentEncode } from "./encode";

// ----------------------------------------------------------
// LICENSE: This code partially belongs to oauth-1.0a package
// ----------------------------------------------------------

const NONCE_LEN = 32;

export type OAuth1Tokens = {
  key: string;
  secret: string;
};

export type OAuth1MakerArgs = {
  consumerKeys: OAuth1Tokens;
};

export type OAuth1RequestOptions = {
  url: string;
  method: string;
  data?: any;
};

export type OAuth1AuthInfo = {
  oauth_consumer_key: string;
  oauth_nonce: string;
  oauth_signature_method: string;
  oauth_timestamp: number;
  oauth_version: string;
  oauth_token: string;
  oauth_signature: string;
};

export function authorizeOAuth1(
  request: OAuth1RequestOptions,
  appConsumerTokens: OAuth1Tokens,
  accessTokens: Partial<OAuth1Tokens> = {},
) {
  const oauthInfo: Partial<OAuth1AuthInfo> = {
    oauth_consumer_key: appConsumerTokens.key,
    oauth_nonce: getNonce(),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: getTimestampInSec(),
    oauth_version: "1.0",
  };

  if (accessTokens.key !== undefined) {
    oauthInfo.oauth_token = accessTokens.key;
  }

  if (!request.data) {
    request.data = {};
  }

  oauthInfo.oauth_signature = getSignature(
    request,
    appConsumerTokens.secret,
    accessTokens.secret,
    oauthInfo as OAuth1AuthInfo,
  );

  return oauthInfo as OAuth1AuthInfo;
}

export function toHeader(oauthInfo: OAuth1AuthInfo) {
  const sorted = sortObject(oauthInfo);
  let header_value = "OAuth ";

  for (const element of sorted) {
    if (element.key.indexOf("oauth_") !== 0) {
      continue;
    }

    header_value +=
      percentEncode(element.key) +
      '="' +
      percentEncode(element.value as string) +
      '",';
  }

  return {
    // Remove the last ,
    Authorization: header_value.slice(0, header_value.length - 1),
  };
}

function getNonce() {
  const wordCharacters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for (let i = 0; i < NONCE_LEN; i++) {
    result += wordCharacters[Math.trunc(Math.random() * wordCharacters.length)];
  }
  return result;
}

function getTimestampInSec() {
  return Math.trunc(new Date().getTime() / 1000);
}

function getSignature(
  request: OAuth1RequestOptions,
  consumerSecret: string,
  tokenSecret: string | undefined,
  oauthInfo: OAuth1AuthInfo,
) {
  return hash(
    getBaseString(request, oauthInfo),
    getSigningKey(consumerSecret, tokenSecret),
  );
}

function getSigningKey(
  consumerSecret: string,
  tokenSecret: string | undefined,
) {
  return percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret || "");
}

function getBaseString(
  request: OAuth1RequestOptions,
  oauthInfo: OAuth1AuthInfo,
) {
  return (
    request.method.toUpperCase() +
    "&" +
    percentEncode(getBaseUrl(request.url)) +
    "&" +
    percentEncode(getParameterString(request, oauthInfo))
  );
}

function getParameterString(
  request: OAuth1RequestOptions,
  oauthInfo: OAuth1AuthInfo,
) {
  const baseStringData = sortObject(
    percentEncodeData(
      mergeObject(
        oauthInfo,
        mergeObject(request.data, deParamUrl(request.url)),
      ),
    ),
  );

  let dataStr = "";

  for (const { key, value } of baseStringData) {
    // check if the value is an array
    // this means that this key has multiple values
    if (value && Array.isArray(value)) {
      // sort the array first
      value.sort();

      let valString = "";
      // serialize all values for this key: e.g. formkey=formvalue1&formkey=formvalue2
      value.forEach((item, i) => {
        valString += key + "=" + item;
        if (i < value.length) {
          valString += "&";
        }
      });

      dataStr += valString;
    } else {
      dataStr += key + "=" + value + "&";
    }
  }

  // Remove the last character
  return dataStr.slice(0, dataStr.length - 1);
}

function getBaseUrl(url: string) {
  return url.split("?")[0];
}

// Helper functions //

function mergeObject<A extends object, B extends object>(
  obj1: A,
  obj2: B,
): A & B {
  return {
    ...(obj1 || {}),
    ...(obj2 || {}),
  };
}

function sortObject<T extends object>(data: T) {
  return Object.keys(data)
    .sort()
    .map((key) => ({ key, value: data[key as keyof typeof data] }));
}

function deParam(string: string) {
  const split = string.split("&");
  const data: { [key: string]: string | string[] } = {};

  for (const coupleKeyValue of split) {
    const [key, value = ""] = coupleKeyValue.split("=");

    // check if the key already exists
    // this can occur if the QS part of the url contains duplicate keys like this: ?formkey=formvalue1&formkey=formvalue2
    if (data[key]) {
      // the key exists already
      if (!Array.isArray(data[key])) {
        // replace the value with an array containing the already present value
        data[key] = [data[key] as string];
      }
      // and add the new found value to it
      (data[key] as string[]).push(decodeURIComponent(value));
    } else {
      // it doesn't exist, just put the found value in the data object
      data[key] = decodeURIComponent(value);
    }
  }

  return data;
}

function deParamUrl(url: string) {
  const tmp = url.split("?");

  if (tmp.length === 1) return {};

  return deParam(tmp[1]);
}

function percentEncodeData<T>(data: T): T {
  const result: any = {};

  for (const key in data) {
    let value: any = data[key];

    // check if the value is an array
    if (value && Array.isArray(value)) {
      value = value.map((v) => percentEncode(v));
    } else {
      value = percentEncode(value);
    }

    result[percentEncode(key)] = value;
  }

  return result;
}

export function hash(base: string, key: string) {
  return createHmac("sha1", key).update(base).digest("base64");
}
