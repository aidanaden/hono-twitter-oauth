import { Hono } from "hono";
import { env } from "hono/adapter";
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
const SECURE_COOKIE_OPTIONS: CookieOptions = {
  path: "/",
  secure: false,
  // Omit if localhost
  // domain: "localhost",
  httpOnly: false,
  maxAge: 1000,
  expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
  sameSite: "Lax",
};

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

const app = new Hono();

app.get("/health", (c) => {
  return c.json({ status: 200, message: "im hella healthy!" }, 200);
});

app.get("/api/signin", async (c) => {
  // NAME is the value written in `wrangler.toml` on Cloudflare
  const { TWITTER_APP_KEY, TWITTER_APP_SECRET, COOKIE_SECRET } =
    env<EnvVars>(c);

  const { oauth_token_secret, url } = await generateOAuth1RedirectUrl(
    {
      callbackUrl: getCallbackUrl(c.req.url),
      appConsumerTokens: { key: TWITTER_APP_KEY, secret: TWITTER_APP_SECRET },
    },
    { linkMode: "authorize" },
  );

  // Signed cookies
  await setSignedCookie(
    c,
    COOKIE_KEYS.OAUTH_SECRET,
    oauth_token_secret,
    COOKIE_SECRET,
    {
      ...SECURE_COOKIE_OPTIONS,
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );
  return c.redirect(url);
});

app.get("/api/signout", async (c) => {
  deleteCookie(c, COOKIE_KEYS.ACCESS_TOKEN, {
    ...SECURE_COOKIE_OPTIONS,
    expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
  });
  deleteCookie(c, COOKIE_KEYS.ACCESS_SECRET, {
    ...SECURE_COOKIE_OPTIONS,
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

  const { TWITTER_APP_KEY, TWITTER_APP_SECRET, COOKIE_SECRET } =
    env<EnvVars>(c);

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
    oauthToken,
    oauthVerifier,
    appConsumerTokens: {
      key: TWITTER_APP_KEY,
      secret: TWITTER_APP_SECRET,
    },
  });

  // Set perm access token for verification
  await setSignedCookie(
    c,
    COOKIE_KEYS.ACCESS_TOKEN,
    oauthResult.oauth_token,
    COOKIE_SECRET,
    {
      ...SECURE_COOKIE_OPTIONS,
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );

  await setSignedCookie(
    c,
    COOKIE_KEYS.ACCESS_SECRET,
    oauthResult.oauth_token_secret,
    COOKIE_SECRET,
    {
      ...SECURE_COOKIE_OPTIONS,
      expires: new Date(Date.UTC(2024, 11, 24, 10, 30, 59, 900)),
    },
  );
  return c.json(oauthResult);
});

app.get("/api/me", async (c) => {
  const { TWITTER_APP_KEY, TWITTER_APP_SECRET, COOKIE_SECRET } =
    env<EnvVars>(c);

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
