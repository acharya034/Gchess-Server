"use strict";

// Configure this with your registered Lichess OAuth application.
const CONFIG = {
  oauthAuthorizeUrl: "https://lichess.org/oauth",
  oauthTokenUrl: "https://lichess.org/api/token",
  clientId: "esp32-smart-chessboard",
  redirectUri: "https://acharya034.github.io/Gchess-Server/",
  scope: "board:play",

  startPath: "/pair/start",
  tokenPath: "/pair/token",
  statusPath: "/pair/status"
};

const $ = id => document.getElementById(id);
const params = new URLSearchParams(window.location.search);

let deviceIp = params.get("d") || "";
let busy = false;

function setStatus(status, message = "") {
  $("status").textContent = status;
  $("message").textContent = message;
}

function showFailure(error) {
  busy = false;
  setStatus("Failed", error.message || String(error));

  $("retry").hidden = false;
  $("connect").disabled = false;
  $("cancel").hidden = true;
}

function validIPv4(ip) {
  const parts = ip.split(".");

  return parts.length === 4 &&
    parts.every(part =>
      /^\d{1,3}$/.test(part) &&
      Number(part) >= 0 &&
      Number(part) <= 255
    );
}

function boardUrl(path) {
  if (!validIPv4(deviceIp)) {
    throw new Error("Missing or invalid ESP32 IP address. Scan the board QR code again.");
  }

  // Local-network HTTP is for initial testing.
  return `http://${deviceIp}${path}`;
}

async function boardRequest(path, body) {
  const response = await fetch(boardUrl(path), {
    method: "POST",
    mode: "cors",
    credentials: "omit",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  });

  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error("ESP32 returned an invalid response.");
  }

  if (!response.ok || data.ok !== true) {
    throw new Error(
      data.error || `ESP32 returned HTTP ${response.status}.`
    );
  }

  return data;
}

// Create random values for OAuth PKCE.
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createCodeChallenge(verifier) {
  const bytes = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return base64url(new Uint8Array(digest));
}

function clearOAuthState() {
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("oauth_verifier");
  sessionStorage.removeItem("board_ip");
  sessionStorage.removeItem("board_session");
}

// STEP 1: Start Lichess authorization.
async function startOAuth() {
  if (busy) return;

  try {
    if (!validIPv4(deviceIp)) {
      throw new Error("The ESP32 IP address is missing or invalid. Scan its QR code again.");
    }

    if (!CONFIG.clientId || CONFIG.clientId.startsWith("REPLACE_")) {
      throw new Error("Configure your registered Lichess client ID.");
    }

    if (!window.isSecureContext || !crypto.subtle) {
      throw new Error("Secure HTTPS is required for OAuth PKCE.");
    }

    busy = true;
    $("connect").disabled = true;
    $("retry").hidden = true;
    $("cancel").hidden = false;

    setStatus("Authorizing", "Preparing secure Lichess authorization...");

    // Preserve the board IP across the Lichess redirect.
    sessionStorage.setItem("board_ip", deviceIp);

    const verifier = base64url(randomBytes(32));
    const challenge = await createCodeChallenge(verifier);
    const state = base64url(randomBytes(32));

    sessionStorage.setItem("oauth_verifier", verifier);
    sessionStorage.setItem("oauth_state", state);

    const authUrl = new URL(CONFIG.oauthAuthorizeUrl);

    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", CONFIG.clientId);
    authUrl.searchParams.set("redirect_uri", CONFIG.redirectUri);
    authUrl.searchParams.set("scope", CONFIG.scope);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    window.location.assign(authUrl.toString());
  } catch (error) {
    showFailure(error);
  }
}

// STEP 2: Validate the access token with Lichess.
async function validateLichessAccount(accessToken) {
  const response = await fetch("https://lichess.org/api/account", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json"
    },
    credentials: "omit",
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(
      `Lichess account validation failed: HTTP ${response.status}.`
    );
  }

  const account = await response.json();

  if (!account.id || !account.username) {
    throw new Error("Lichess returned an invalid account response.");
  }

  return {
    id: account.id,
    username: account.username
  };
}

// STEP 3: Handle the return from Lichess.
async function handleOAuthReturn() {
  const query = new URLSearchParams(window.location.search);

  const code = query.get("code");
  const returnedState = query.get("state");
  const oauthError = query.get("error");

  if (!code && !oauthError) return;

  // Recover the board IP saved before the redirect.
  deviceIp = sessionStorage.getItem("board_ip") || deviceIp;

  // Remove OAuth parameters from the address bar.
  history.replaceState(
    {},
    document.title,
    window.location.pathname + window.location.hash
  );

  try {
    if (oauthError) {
      throw new Error("Lichess authorization was denied or cancelled.");
    }

    const expectedState = sessionStorage.getItem("oauth_state");
    const verifier = sessionStorage.getItem("oauth_verifier");

    if (!expectedState || returnedState !== expectedState || !verifier) {
      throw new Error("OAuth state verification failed. Please try again.");
    }

    if (!validIPv4(deviceIp)) {
      throw new Error("The original ESP32 IP is missing. Scan the board QR code again.");
    }

    busy = true;
    $("connect").disabled = true;
    $("retry").hidden = true;
    $("cancel").hidden = false;

    setStatus("Authorizing", "Exchanging the authorization code with Lichess...");

    // Exchange the authorization code for an access token.
    const tokenResponse = await fetch(CONFIG.oauthTokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      credentials: "omit",
      cache: "no-store",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: CONFIG.redirectUri,
        client_id: CONFIG.clientId,
        code_verifier: verifier
      })
    });

    if (!tokenResponse.ok) {
      throw new Error(
        `Lichess token exchange failed: HTTP ${tokenResponse.status}.`
      );
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("Lichess did not return an access token.");
    }

    setStatus("Verifying account", "Checking the Lichess account...");

    const account = await validateLichessAccount(tokenData.access_token);

    setStatus(
      "Account verified",
      `Lichess account: ${account.username}. Starting board pairing...`
    );

    // Start a pairing session. No pairing secret is sent.
    const session = await boardRequest(CONFIG.startPath, {});

    if (!session.sessionId) {
      throw new Error("ESP32 did not return a pairing session ID.");
    }

    sessionStorage.setItem("board_session", session.sessionId);

    // Send the token and session ID to the ESP32.
    setStatus(
      "Pairing",
      `Sending the token for ${account.username} to the chessboard...`
    );

    const result = await boardRequest(CONFIG.tokenPath, {
      sessionId: session.sessionId,
      accessToken: tokenData.access_token
    });

    if (result.stored !== true) {
      throw new Error("ESP32 did not confirm that the token was stored.");
    }

    clearOAuthState();

    setStatus(
      "Connected",
      `Lichess account ${account.username} verified. The chessboard confirmed token storage.`
    );

    $("connect").disabled = false;
    $("cancel").hidden = true;
    $("retry").hidden = true;
  } catch (error) {
    showFailure(error);
  } finally {
    busy = false;
  }
}

// Display the board IP.
$("deviceIp").textContent = validIPv4(deviceIp)
  ? deviceIp
  : "Missing or invalid";

// Wire up the HTML buttons.
$("connect").addEventListener("click", startOAuth);

$("retry").addEventListener("click", () => {
  clearOAuthState();

  // Read the IP from the current QR URL.
  deviceIp = params.get("d") || "";

  // If retrying after an OAuth redirect, the URL may no longer contain
  // the device parameter. Ask the user to scan the QR code again.
  if (!validIPv4(deviceIp)) {
    setStatus("Scan QR again", "Open the website using the ESP32 QR code.");
    $("retry").hidden = false;
    $("connect").disabled = false;
    return;
  }

  startOAuth();
});

$("cancel").addEventListener("click", () => {
  clearOAuthState();

  setStatus("Not connected", "Authorization cancelled. You can start again.");

  $("connect").disabled = false;
  $("retry").hidden = true;
  $("cancel").hidden = true;
});

// Process the redirect from Lichess, if present.
handleOAuthReturn().catch(showFailure);
