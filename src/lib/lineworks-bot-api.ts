/**
 * LINE WORKS Bot API client
 * JWT generation (Web Crypto API) + OAuth2 token + Rich Menu API
 *
 * Credentials are fetched from DB via gRPC (BotConfigService.GetConfigWithSecrets)
 */

const AUTH_TOKEN_ENDPOINT = "https://auth.worksmobile.com/oauth2/v2.0/token";

/** Bot credentials from DB (decrypted by rust-logi) */
export interface BotCredentials {
  clientId: string;
  clientSecret: string;
  serviceAccount: string;
  privateKey: string;
  botId: string;
}

// --- Base64url helpers ---

function base64urlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlEncodeString(str: string): string {
  return base64urlEncode(new TextEncoder().encode(str));
}

// --- PEM parsing ---

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const normalized = pem.replace(/\\n/g, "\n");
  const lines = normalized
    .split("\n")
    .filter((line) => !line.startsWith("-----") && line.trim().length > 0);
  const base64 = lines.join("");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// --- JWT generation (Web Crypto API, RS256) ---

async function createJwt(creds: BotCredentials): Promise<string> {
  const header = base64urlEncodeString(JSON.stringify({ alg: "RS256", typ: "JWT" }));

  const now = Math.floor(Date.now() / 1000);
  const payload = base64urlEncodeString(
    JSON.stringify({
      iss: creds.clientId,
      sub: creds.serviceAccount,
      iat: now,
      exp: now + 60,
    }),
  );

  const signingInput = `${header}.${payload}`;

  const keyData = pemToArrayBuffer(creds.privateKey);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${base64urlEncode(signature)}`;
}

// --- OAuth2 token ---

async function getAccessToken(creds: BotCredentials): Promise<string> {
  const jwt = await createJwt(creds);

  const params = new URLSearchParams({
    assertion: jwt,
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    scope: "bot",
  });

  const res = await fetch(AUTH_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Token issue failed: ${res.status} ${body}`);
  }

  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}

// --- Rich Menu API helpers ---

function botBaseUrl(creds: BotCredentials): string {
  return `https://www.worksapis.com/v1.0/bots/${creds.botId}`;
}

async function botFetch(
  creds: BotCredentials,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = await getAccessToken(creds);
  const url = `${botBaseUrl(creds)}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...init.headers,
    },
  });
  return res;
}

// --- Rich Menu types ---

export interface RichMenuBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface RichMenuAction {
  type: "uri" | "postback" | "message" | "copy";
  label?: string;
  uri?: string;
  data?: string;
  displayText?: string;
  text?: string;
  copyText?: string;
}

export interface RichMenuArea {
  bounds: RichMenuBounds;
  action: RichMenuAction;
}

export interface RichMenu {
  richmenuId: string;
  richmenuName: string;
  size: { width: number; height: number };
  areas: RichMenuArea[];
}

export interface RichMenuCreate {
  richmenuName: string;
  size: { width: number; height: number };
  areas: RichMenuArea[];
}

// --- Rich Menu API functions ---

export async function listRichMenus(creds: BotCredentials): Promise<RichMenu[]> {
  const res = await botFetch(creds, "/richmenus?count=100");
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`listRichMenus failed: ${res.status} ${body}`);
  }
  const data = (await res.json()) as { richmenus: RichMenu[] };
  return data.richmenus || [];
}

export async function createRichMenu(
  creds: BotCredentials,
  menu: RichMenuCreate,
): Promise<RichMenu> {
  const res = await botFetch(creds, "/richmenus", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(menu),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`createRichMenu failed: ${res.status} ${body}`);
  }
  return (await res.json()) as RichMenu;
}

export async function deleteRichMenu(
  creds: BotCredentials,
  richmenuId: string,
): Promise<void> {
  const res = await botFetch(creds, `/richmenus/${richmenuId}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`deleteRichMenu failed: ${res.status} ${body}`);
  }
}

export async function uploadImage(
  creds: BotCredentials,
  richmenuId: string,
  imageData: ArrayBuffer,
  fileName: string,
): Promise<void> {
  // Get a single access token and reuse for all 3 steps
  const accessToken = await getAccessToken(creds);
  const base = botBaseUrl(creds);

  // Step 1: Get upload URL
  const attachRes = await fetch(`${base}/attachments`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fileName }),
  });
  if (!attachRes.ok) {
    const body = await attachRes.text();
    throw new Error(`attachments failed: ${attachRes.status} ${body}`);
  }
  const attachData = (await attachRes.json()) as {
    fileId: string;
    uploadUrl: string;
  };
  console.log(JSON.stringify({ event: "upload_step1", fileId: attachData.fileId, uploadUrl: attachData.uploadUrl }));

  // Step 2: Upload binary to uploadUrl (POST multipart/form-data per LINE WORKS spec)
  const contentType = fileName.toLowerCase().endsWith(".png")
    ? "image/png"
    : "image/jpeg";
  const blob = new Blob([imageData], { type: contentType });
  const form = new FormData();
  form.append("resourceName", fileName);
  form.append("Filedata", blob, fileName);

  const uploadRes = await fetch(attachData.uploadUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
    body: form,
  });
  const uploadBody = await uploadRes.text();
  console.log(JSON.stringify({ event: "upload_step2", status: uploadRes.status, body: uploadBody }));
  if (!uploadRes.ok) {
    throw new Error(`image upload failed: ${uploadRes.status} ${uploadBody}`);
  }

  // Use fileId from upload response if available, fallback to Step 1's fileId
  let fileId = attachData.fileId;
  try {
    const uploadJson = JSON.parse(uploadBody);
    if (uploadJson.fileId) {
      fileId = uploadJson.fileId;
      console.log(JSON.stringify({ event: "upload_step2_fileId", step1: attachData.fileId, step2: uploadJson.fileId, match: attachData.fileId === uploadJson.fileId }));
    }
  } catch {
    // upload response may not be JSON
  }

  // Step 3: Associate image with richmenu
  const imageRes = await fetch(`${base}/richmenus/${richmenuId}/image`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fileId }),
  });
  const imageBody = await imageRes.text();
  console.log(JSON.stringify({ event: "upload_step3", status: imageRes.status, body: imageBody, fileId }));
  if (!imageRes.ok) {
    throw new Error(`image association failed: ${imageRes.status} ${imageBody}`);
  }
}

/** Check if a rich menu has an image by trying to GET the image endpoint */
export async function checkRichMenuImage(
  creds: BotCredentials,
  richmenuId: string,
): Promise<boolean> {
  try {
    const res = await botFetch(creds, `/richmenus/${richmenuId}/image`);
    console.log(JSON.stringify({ event: "check_image", richmenuId, status: res.status, contentType: res.headers.get("content-type"), contentLength: res.headers.get("content-length") }));
    return res.ok;
  } catch {
    return false;
  }
}

export async function setDefaultRichMenu(
  creds: BotCredentials,
  richmenuId: string,
): Promise<void> {
  const res = await botFetch(creds, `/richmenus/${richmenuId}/set-default`, {
    method: "POST",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`setDefault failed: ${res.status} ${body}`);
  }
}

export async function getDefaultRichMenu(
  creds: BotCredentials,
): Promise<{ defaultRichmenuId: string } | null> {
  const res = await botFetch(creds, "/richmenus/default");
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`getDefault failed: ${res.status} ${body}`);
  }
  return (await res.json()) as { defaultRichmenuId: string };
}

export async function deleteDefaultRichMenu(creds: BotCredentials): Promise<void> {
  const res = await botFetch(creds, "/richmenus/default", {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 404) {
    const body = await res.text();
    throw new Error(`deleteDefault failed: ${res.status} ${body}`);
  }
}
