/**
 * LINE WORKS Bot API client (Rich Menu API + MCP `lineworks_get` の素通し GET)。
 *
 * access token は alc-lineworks worker の `POST /api/internal/lineworks/token` が出す
 * (`lineworks-bot-creds.ts::getBotAccess`)。Client Secret と Private Key は auth-worker に
 * 来ない — JWT の署名も OAuth2 の token 交換も auth-worker では行わない
 * (Refs ohishi-exp/rust-leave-worker#1)。
 */

/** alc-lineworks が出した access token と、その token の Bot の id。token は応答・ログに出さない。 */
export interface BotAccess {
  accessToken: string;
  botId: string;
}

/**
 * `https://www.worksapis.com` 配下への GET を、呼び手が取った token で行う (MCP tool
 * `lineworks_get` 用)。`url` は `resolveLineworksGetTarget` で検証済みのものだけを渡すこと。
 */
export async function worksApiGet(accessToken: string, url: string): Promise<Response> {
  return fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
}

// --- Rich Menu API helpers ---

function botBaseUrl(bot: BotAccess): string {
  return `https://www.worksapis.com/v1.0/bots/${bot.botId}`;
}

async function botFetch(
  bot: BotAccess,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const url = `${botBaseUrl(bot)}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${bot.accessToken}`,
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

export async function listRichMenus(bot: BotAccess): Promise<RichMenu[]> {
  const res = await botFetch(bot, "/richmenus?count=100");
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`listRichMenus failed: ${res.status} ${body}`);
  }
  const data = (await res.json()) as { richmenus: RichMenu[] };
  return data.richmenus || [];
}

export async function createRichMenu(
  bot: BotAccess,
  menu: RichMenuCreate,
): Promise<RichMenu> {
  const res = await botFetch(bot, "/richmenus", {
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
  bot: BotAccess,
  richmenuId: string,
): Promise<void> {
  const res = await botFetch(bot, `/richmenus/${richmenuId}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`deleteRichMenu failed: ${res.status} ${body}`);
  }
}

export async function uploadImage(
  bot: BotAccess,
  richmenuId: string,
  imageData: ArrayBuffer,
  fileName: string,
): Promise<void> {
  // 3 段とも同じ token を使う
  const accessToken = bot.accessToken;
  const base = botBaseUrl(bot);

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
  bot: BotAccess,
  richmenuId: string,
): Promise<boolean> {
  try {
    const res = await botFetch(bot, `/richmenus/${richmenuId}/image`);
    console.log(JSON.stringify({ event: "check_image", richmenuId, status: res.status, contentType: res.headers.get("content-type"), contentLength: res.headers.get("content-length") }));
    return res.ok;
  } catch {
    return false;
  }
}

export async function setDefaultRichMenu(
  bot: BotAccess,
  richmenuId: string,
): Promise<void> {
  const res = await botFetch(bot, `/richmenus/${richmenuId}/set-default`, {
    method: "POST",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`setDefault failed: ${res.status} ${body}`);
  }
}

export async function getDefaultRichMenu(
  bot: BotAccess,
): Promise<{ defaultRichmenuId: string } | null> {
  const res = await botFetch(bot, "/richmenus/default");
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`getDefault failed: ${res.status} ${body}`);
  }
  return (await res.json()) as { defaultRichmenuId: string };
}

export async function deleteDefaultRichMenu(bot: BotAccess): Promise<void> {
  const res = await botFetch(bot, "/richmenus/default", {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 404) {
    const body = await res.text();
    throw new Error(`deleteDefault failed: ${res.status} ${body}`);
  }
}
