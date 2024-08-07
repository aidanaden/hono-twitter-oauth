import { Buffer } from "node:buffer";

export type TRequestQuery = Record<
  string,
  string | number | boolean | string[] | undefined
>;
export type TRequestStringQuery = Record<string, string>;
export type TRequestBody = Record<string, any> | Buffer;
export type TBodyMode = "json" | "url" | "form-data" | "raw";

export type RequestTokenArgs = {
  authAccessType: "read" | "write";
  linkMode: "authenticate" | "authorize";
  forceLogin: boolean;
  screenName: string;
};

export type RequestTokenResult = {
  oauth_token: string;
  oauth_token_secret: string;
  oauth_callback_confirmed: "true";
};

export type AccessTokenResult = {
  oauth_token: string;
  oauth_token_secret: string;
  user_id: string;
  screen_name: string;
};

export type LoginResult = {
  userId: string;
  screenName: string;
  accessToken: string;
  accessSecret: string;
  client: any;
};

export type UserV1 = {
  id_str: string;
  id: number;
  name: string;
  screen_name: string;
  location: string;
  derived?: any;
  url: string | null;
  description: string | null;
  protected: boolean;
  verified: boolean;
  followers_count: number;
  friends_count: number;
  listed_count: number;
  favourites_count: number;
  statuses_count: number;
  created_at: string;
  profile_banner_url: string;
  profile_image_url_https: string;
  default_profile: boolean;
  default_profile_image: boolean;
  withheld_in_countries: string[];
  withheld_scope: string;
  entities?: UserEntitiesV1;

  /** Only on account/verify_credentials with include_email: true */
  email?: string;
};

export interface UserEntitiesV1 {
  url?: { urls: UrlEntityV1[] };
  description?: { urls: UrlEntityV1[] };
}

export interface UrlEntityV1 {
  display_url: string;
  expanded_url: string;
  indices: [number, number];
  url: string;
  unwound?: {
    url: string;
    status: number;
    title: string;
    description: string;
  };
}
