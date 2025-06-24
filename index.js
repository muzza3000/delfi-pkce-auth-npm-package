
const crypto = require("crypto");

let config = {};

function initialize(userConfig) {
  config = {
    ...userConfig,
    authorizationEndpoint: "https://csi.slb.com/v2/auth",
    tokenEndpoint: "https://csi.slb.com/v2/token"
  };
}

function base64URLEncode(buffer) {
  return buffer.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function generateCodeVerifier() {
  return base64URLEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  return base64URLEncode(hash);
}

function getAuthUrl(codeChallenge) {
  const url = new URL(config.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("scope", `openid ${config.audience}`);
  return url.toString();
}

async function exchangeCodeForToken(code, codeVerifier) {
  const fetch = require('node-fetch');

  const response = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code,
      redirect_uri: config.redirectUri,
      code_verifier: codeVerifier
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch token: ${response.statusText} - ${errorText}`);
  }

  return await response.json();
};

// Helper function to return to the app if there is a valid token in the session.
function getAccessToken(req) {
  return req.session?.token || null;
}


module.exports = {
  initialize,
  generateCodeVerifier,
  generateCodeChallenge,
  getAuthUrl,
  exchangeCodeForToken,
  getAccessToken
};
