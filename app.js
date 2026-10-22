
"use strict";

// Configure this with your registered Lichess OAuth application.
const CONFIG = {
  authorizeUrl: "https://lichess.org/oauth",
  tokenUrl: "https://lichess.org/api/token",
  accountUrl: "https://lichess.org/api/account",

  // Replace with your actual registered public OAuth client ID.
  clientId: "esp32-smart-chessboard",
  // Must exactly match the redirect URI registered for your app.
  redirectUri: window.location.origin + window.location.pathname,

  scope: "board:play",

  startPath: "/pair/start",
  tokenPath: "/pair/token"
};

const $ = id => document.getElementById(id);

const params = new URLSearchParams(window.location.search);

let deviceIp = params.get("device") || "";
let pairSecret = params.get("pair") || "";
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
    throw new Error("Missing or invalid ESP32 IP address.");
  }

  // HTTP is suitable only for initial local-network testing.
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

  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes
  );

  return base64url(new Uint8Array(digest));
}

function clearOAuthState() {
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("oauth_verifier");
  sessionStorage.removeItem("board_ip");
  sessionStorage.removeItem("pair_secret");
}

// STEP 1: Start Lichess authorization.
async function startOAuth() {
  if (busy) return;

  try {
    if (!validIPv4(deviceIp)) {
      throw new Error("The ESP32 IP address is missing or invalid.");
    }

    if (!/^[A-Za-z0-9]{16,}$/.test(pairSecret)) {
      throw new Error("The pairing secret is missing or invalid.");
    }

    if (
      !CONFIG.clientId ||
      CONFIG.clientId.startsWith("REPLACE_")
    ) {
      throw new Error("Configure your registered Lichess client ID.");
    }

    if (!window.isSecureContext || !crypto.subtle) {
      throw new Error(
        "Secure HTTPS is required for OAuth PKCE. " +
        "Your current local HTTP website does not meet this requirement."
      );
    }

    busy = true;
    $("connect").disabled = true;
    $("retry").hidden = true;
    $("cancel").hidden = false;

    setStatus(
      "Authorizing",
      "Preparing secure Lichess authorization..."
    );

    // Save the board information across the Lichess redirect.
    sessionStorage.setItem("board_ip", deviceIp);
    sessionStorage.setItem("pair_secret", pairSecret);

    const verifier = base64url(randomBytes(32));
    const challenge = await createCodeChallenge(verifier);
    const state = base64url(randomBytes(32));

    sessionStorage.setItem("oauth_verifier", verifier);
    sessionStorage.setItem("oauth_state", state);

    const authUrl = new URL(CONFIG.authorizeUrl);

    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", CONFIG.clientId);
    authUrl.searchParams.set("redirect_uri", CONFIG.redirectUri);
    authUrl.searchParams.set("scope", CONFIG.scope);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    // Navigate to Lichess. The user signs in on lichess.org.
    window.location.assign(authUrl.toString());

  } catch (error) {
    showFailure(error);
  }
}

// STEP 2: Validate the access token with Lichess.
async function validateLichessAccount(accessToken) {
  const response = await fetch(CONFIG.accountUrl, {
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

  // Recover the original board information saved before redirecting.
  deviceIp = sessionStorage.getItem("board_ip") || "";
  pairSecret = sessionStorage.getItem("pair_secret") || "";

  // Remove authorization parameters from the address bar.
  history.replaceState(
    {},
    document.title,
    window.location.pathname + window.location.hash
  );

  try {
    if (oauthError) {
      throw new Error(
        "Lichess authorization was denied or cancelled."
      );
    }

    const expectedState = sessionStorage.getItem("oauth_state");
    const verifier = sessionStorage.getItem("oauth_verifier");

    if (
      !expectedState ||
      returnedState !== expectedState ||
      !verifier
    ) {
      throw new Error(
        "OAuth state verification failed. Please try again."
      );
    }

    if (!validIPv4(deviceIp) || !pairSecret) {
      throw new Error(
        "The original board pairing information is missing. Scan the QR again."
      );
    }

    busy = true;
    $("connect").disabled = true;
    $("retry").hidden = true;
    $("cancel").hidden = false;

    setStatus(
      "Authorizing",
      "Exchanging the authorization code with Lichess..."
    );

    // Exchange the authorization code for an access token.
    const tokenResponse = await fetch(CONFIG.tokenUrl, {
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

    // Verify the token and get the account's actual username.
    setStatus("Verifying account", "Checking the Lichess account...");

    const account = await validateLichessAccount(
      tokenData.access_token
    );

    setStatus(
      "Account verified",
      `Lichess account: ${account.username}. Starting board pairing...`
    );

    // Start a fresh pairing session AFTER OAuth finishes.
    const session = await boardRequest(CONFIG.startPath, {
      pairSecret
    });

    if (!session.sessionId) {
      throw new Error(
        "ESP32 did not return a pairing session ID."
      );
    }

    // Send the verified account's token to the ESP32.
    setStatus(
      "Pairing",
      `Sending the token for ${account.username} to the chessboard...`
    );

    const result = await boardRequest(CONFIG.tokenPath, {
      sessionId: session.sessionId,
      pairSecret,
      accessToken: tokenData.access_token
    });

    if (result.stored !== true) {
      throw new Error(
        "ESP32 did not confirm that the token was stored."
      );
    }

    clearOAuthState();

    sessionStorage.removeItem("board_session");

    setStatus(
      "Connected",
      `Lichess account ${account.username} verified. ` +
      "The chessboard confirmed token storage."
    );

    $("cancel").hidden = true;
    $("retry").hidden = true;

  } catch (error) {
    showFailure(error);
  } finally {
    busy = false;
  }
}

// Show the board IP on the page.
$("deviceIp").textContent = validIPv4(deviceIp)
  ? deviceIp
  : "Missing or invalid";

// Wire up the existing HTML buttons.
$("connect").addEventListener("click", startOAuth);

$("retry").addEventListener("click", () => {
  clearOAuthState();

  // Restore original QR parameters if retrying on the initial page.
  deviceIp = params.get("device") || "";
  pairSecret = params.get("pair") || "";

  startOAuth();
});

$("cancel").addEventListener("click", () => {
  clearOAuthState();

  setStatus(
    "Not connected",
    "Authorization cancelled. You can start again."
  );

  $("connect").disabled = false;
  $("retry").hidden = true;
  $("cancel").hidden = true;
});

// If Lichess redirected back with an authorization code, process it.
handleOAuthReturn().catch(showFailure);
