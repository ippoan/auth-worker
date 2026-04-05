/**
 * Rich Menu API endpoints
 * Client JS → auth-worker API → REST GetConfigSecrets → lineworks-bot-api → LINE WORKS API
 */

import type { Env } from "../index";
import type { BotCredentials, RichMenuArea } from "../lib/lineworks-bot-api";
import {
  listRichMenus,
  createRichMenu,
  deleteRichMenu,
  uploadImage,
  checkRichMenuImage,
  setDefaultRichMenu,
  getDefaultRichMenu,
  deleteDefaultRichMenu,
} from "../lib/lineworks-bot-api";

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  return null;
}

/** Fetch decrypted BotCredentials from rust-alc-api REST API */
async function getCredsFromConfig(
  env: Env,
  token: string,
  botConfigId: string,
): Promise<BotCredentials> {
  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/admin/bot/configs/${botConfigId}/secrets`,
    { headers: { Authorization: `Bearer ${token}` } },
  );

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to get bot config: ${resp.status} ${text}`);
  }

  const c = (await resp.json()) as {
    client_id: string;
    client_secret: string;
    service_account: string;
    private_key: string;
    bot_id: string;
  };

  return {
    clientId: c.client_id,
    clientSecret: c.client_secret,
    serviceAccount: c.service_account,
    privateKey: c.private_key,
    botId: c.bot_id,
  };
}

export async function handleRichMenuList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { botConfigId: string };
  if (!body.botConfigId) {
    return jsonResponse({ error: "botConfigId is required" }, 400);
  }

  console.log(JSON.stringify({ event: "richmenu_list", botConfigId: body.botConfigId }));

  try {
    const creds = await getCredsFromConfig(env, token, body.botConfigId);
    const [richmenus, defaultMenu] = await Promise.all([
      listRichMenus(creds),
      getDefaultRichMenu(creds),
    ]);
    // Check image status for each menu in parallel
    const imageChecks = await Promise.all(
      richmenus.map((m) => checkRichMenuImage(creds, m.richmenuId)),
    );
    const imageStatus: Record<string, boolean> = {};
    richmenus.forEach((m, i) => {
      imageStatus[m.richmenuId] = imageChecks[i] ?? false;
    });
    return jsonResponse({
      richmenus,
      defaultRichmenuId: defaultMenu?.defaultRichmenuId || null,
      imageStatus,
    });
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}

export async function handleRichMenuCreate(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as {
    botConfigId: string;
    richmenuName: string;
    size: { width: number; height: number };
    areas: RichMenuArea[];
  };

  if (!body.botConfigId || !body.richmenuName || !body.size || !body.areas?.length) {
    return jsonResponse(
      { error: "botConfigId, richmenuName, size, and areas are required" },
      400,
    );
  }

  console.log(
    JSON.stringify({
      event: "richmenu_create",
      botConfigId: body.botConfigId,
      name: body.richmenuName,
    }),
  );

  try {
    const creds = await getCredsFromConfig(env, token, body.botConfigId);
    const menu = await createRichMenu(creds, {
      richmenuName: body.richmenuName,
      size: body.size,
      areas: body.areas,
    });
    return jsonResponse(menu);
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}

export async function handleRichMenuDelete(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as {
    botConfigId: string;
    richmenuId: string;
  };

  if (!body.botConfigId || !body.richmenuId) {
    return jsonResponse(
      { error: "botConfigId and richmenuId are required" },
      400,
    );
  }

  console.log(
    JSON.stringify({
      event: "richmenu_delete",
      botConfigId: body.botConfigId,
      richmenuId: body.richmenuId,
    }),
  );

  try {
    const creds = await getCredsFromConfig(env, token, body.botConfigId);
    await deleteRichMenu(creds, body.richmenuId);
    return jsonResponse({ success: true });
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}

export async function handleRichMenuImageUpload(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return jsonResponse({ error: "Invalid multipart form data" }, 400);
  }

  const botConfigId = formData.get("botConfigId") as string;
  const richmenuId = formData.get("richmenuId") as string;
  const imageFile = formData.get("image") as File | null;

  if (!botConfigId || !richmenuId || !imageFile) {
    return jsonResponse(
      { error: "botConfigId, richmenuId, and image are required" },
      400,
    );
  }

  if (imageFile.size > 1024 * 1024) {
    return jsonResponse({ error: "Image must be 1MB or less" }, 400);
  }

  const fileName = imageFile.name;
  const lowerName = fileName.toLowerCase();
  if (!lowerName.endsWith(".png") && !lowerName.endsWith(".jpg") && !lowerName.endsWith(".jpeg")) {
    return jsonResponse({ error: "Image must be JPEG or PNG" }, 400);
  }

  console.log(
    JSON.stringify({
      event: "richmenu_image_upload",
      botConfigId,
      richmenuId,
      fileName,
      size: imageFile.size,
    }),
  );

  try {
    const creds = await getCredsFromConfig(env, token, botConfigId);
    const imageData = await imageFile.arrayBuffer();
    await uploadImage(creds, richmenuId, imageData, fileName);
    return jsonResponse({ success: true });
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}

export async function handleRichMenuDefaultSet(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as {
    botConfigId: string;
    richmenuId: string;
  };

  if (!body.botConfigId || !body.richmenuId) {
    return jsonResponse(
      { error: "botConfigId and richmenuId are required" },
      400,
    );
  }

  console.log(
    JSON.stringify({
      event: "richmenu_default_set",
      botConfigId: body.botConfigId,
      richmenuId: body.richmenuId,
    }),
  );

  try {
    const creds = await getCredsFromConfig(env, token, body.botConfigId);
    await setDefaultRichMenu(creds, body.richmenuId);
    return jsonResponse({ success: true });
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}

export async function handleRichMenuDefaultDelete(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { botConfigId: string };
  if (!body.botConfigId) {
    return jsonResponse({ error: "botConfigId is required" }, 400);
  }

  console.log(
    JSON.stringify({
      event: "richmenu_default_delete",
      botConfigId: body.botConfigId,
    }),
  );

  try {
    const creds = await getCredsFromConfig(env, token, body.botConfigId);
    await deleteDefaultRichMenu(creds);
    return jsonResponse({ success: true });
  } catch (err) {
    if (err instanceof Error) {
      return jsonResponse({ error: err.message }, 500);
    }
    throw err;
  }
}
