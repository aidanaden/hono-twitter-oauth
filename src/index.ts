import { Hono } from "hono";
import { deleteCookie, getSignedCookie, setSignedCookie } from "hono/cookie";
import { CookieOptions } from "hono/utils/cookie";

import {
  generateOAuth1AccessTokens,
  generateOAuth1RedirectUrl,
  getMe,
} from "./twitter";

const COOKIE_KEYS = {
  OAUTH_SECRET: "oauth_secret",
  ACCESS_TOKEN: "access_token",
  ACCESS_SECRET: "access_secret",
};

function getSecureCookieOptions(rawUrl: string): CookieOptions {
  const domain = new URL(rawUrl).host;
  const isLocalHost = domain.includes("localhost");
  return {
    path: "/",
    secure: isLocalHost ? false : true,
    // Omit domain if localhost
    ...(isLocalHost ? {} : { domain }),
    httpOnly: isLocalHost ? false : true,
    maxAge: 1000,
    expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    sameSite: isLocalHost ? "Lax" : "Lax",
  };
}

function getCallbackUrl(rawUrl: string) {
  const url = new URL(rawUrl);
  const host = url.host;
  return `${url.protocol}//${host}/api/auth/callback/twitter`;
}

type EnvVars = {
  TWITTER_APP_KEY: string;
  TWITTER_APP_SECRET: string;
  COOKIE_SECRET: string;
};

const app = new Hono<{ Bindings: EnvVars }>();

app.get("/health", (c) => {
  return c.json({ status: 200, message: "im hella healthy!" }, 200);
});

app.get("/api/signin", async (c) => {
  const TWITTER_APP_KEY = c.env.TWITTER_APP_KEY;
  const TWITTER_APP_SECRET = c.env.TWITTER_APP_SECRET;
  const COOKIE_SECRET = c.env.COOKIE_SECRET;

  const { oauth_token_secret, url } = await generateOAuth1RedirectUrl(
    {
      callbackUrl: getCallbackUrl(c.req.url),
      appConsumerTokens: { key: TWITTER_APP_KEY, secret: TWITTER_APP_SECRET },
    },
    { linkMode: "authorize" },
    c.req.header("cf-connecting-ip") ?? "",
  );

  // Signed cookies
  await setSignedCookie(
    c,
    COOKIE_KEYS.OAUTH_SECRET,
    oauth_token_secret,
    COOKIE_SECRET,
    {
      ...getSecureCookieOptions(c.req.url),
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );
  return c.redirect(url);
});

app.get("/api/signout", async (c) => {
  deleteCookie(c, COOKIE_KEYS.ACCESS_TOKEN, {
    ...getSecureCookieOptions(c.req.url),
    expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
  });
  deleteCookie(c, COOKIE_KEYS.ACCESS_SECRET, {
    ...getSecureCookieOptions(c.req.url),
    expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
  });
  return c.json({ status: 200 }, 200);
});

app.get("/api/auth/callback/twitter", async (c) => {
  // Extract tokens from query string
  const oauthToken = c.req.query("oauth_token");
  const oauthVerifier = c.req.query("oauth_verifier");

  if (!oauthToken || !oauthVerifier) {
    const message = "You denied the app or your session expired!";
    return new Response(JSON.stringify({ status: 400, reason: message }), {
      status: 400,
      statusText: message,
    });
  }

  const TWITTER_APP_KEY = c.env.TWITTER_APP_KEY;
  const TWITTER_APP_SECRET = c.env.TWITTER_APP_SECRET;
  const COOKIE_SECRET = c.env.COOKIE_SECRET;

  // Get the saved oauth_token_secret from session
  const oauthTokenSecret = await getSignedCookie(
    c,
    COOKIE_SECRET,
    COOKIE_KEYS.OAUTH_SECRET,
  );
  if (!oauthTokenSecret) {
    const message = "Missing oauth token secret!";
    return new Response(JSON.stringify({ status: 400, reason: message }), {
      status: 400,
      statusText: message,
    });
  }

  // // Obtain the persistent tokens
  const oauthResult = await generateOAuth1AccessTokens({
    oauthTokens: {
      key: oauthToken,
      secret: oauthTokenSecret,
    },
    oauthVerifier,
    appConsumerTokens: {
      key: TWITTER_APP_KEY,
      secret: TWITTER_APP_SECRET,
    },
    realIp: c.req.header("cf-connecting-ip") ?? "",
    // oauthTokens: {
    //   key: oauthToken,
    //   secret: oauthTokenSecret,
    // },
  });
  console.log({ oauthToken, oauthTokenSecret, oauthResult });

  // Set perm access token for verification
  await setSignedCookie(
    c,
    COOKIE_KEYS.ACCESS_TOKEN,
    oauthResult.oauth_token,
    COOKIE_SECRET,
    {
      ...getSecureCookieOptions(c.req.url),
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );

  await setSignedCookie(
    c,
    COOKIE_KEYS.ACCESS_SECRET,
    oauthResult.oauth_token_secret,
    COOKIE_SECRET,
    {
      ...getSecureCookieOptions(c.req.url),
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );
  return c.json(oauthResult);
});

app.get("/api/me", async (c) => {
  const TWITTER_APP_KEY = c.env.TWITTER_APP_KEY;
  const TWITTER_APP_SECRET = c.env.TWITTER_APP_SECRET;
  const COOKIE_SECRET = c.env.COOKIE_SECRET;

  const accessToken = await getSignedCookie(
    c,
    COOKIE_SECRET,
    COOKIE_KEYS.ACCESS_TOKEN,
  );
  const accessSecret = await getSignedCookie(
    c,
    COOKIE_SECRET,
    COOKIE_KEYS.ACCESS_SECRET,
  );

  if (!accessToken || !accessSecret) {
    const message = "Missing access token or access secret!";
    return new Response(JSON.stringify({ status: 400, reason: message }), {
      status: 400,
      statusText: message,
    });
  }

  const user = await getMe({
    appConsumerTokens: { key: TWITTER_APP_KEY, secret: TWITTER_APP_SECRET },
    accessTokens: { key: accessToken, secret: accessSecret },
  });
  // TODO: query DB for user info and check that
  // it matches with returned user data
  // IF TRUE: return user data to FE
  // ELSE: mismatched cookies, remove
  return c.json(user);
});

export default app;
