import { handleSsoList, handleSsoUpsert, handleSsoDelete } from "./handlers/api-sso";
import { handleBotConfigList, handleBotConfigUpsert, handleBotConfigDelete } from "./handlers/api-bot-config";
import {
  handleUsersList, handleInvitationsList, handleInviteUser,
  handleDeleteInvitation, handleDeleteUser,
} from "./handlers/api-users";
import { handleHealthProxy } from "./handlers/health";
import { handleLoginPage } from "./handlers/login-page";

export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  OAUTH_STATE_SECRET: string;
  AUTH_WORKER_ORIGIN: string;
  ALLOWED_REDIRECT_ORIGINS: string;
  ALC_API_ORIGIN: string;
  VERSION: string;
}

function errorResponse(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    console.log(JSON.stringify({
      event: "request",
      method: request.method,
      path: url.pathname,
      search: url.search,
    }));

    try {
      if (request.method === "GET") {
        switch (url.pathname) {
          case "/api/health":
            return await handleHealthProxy(env);
          case "/login":
            return await handleLoginPage(request, env);
          default:
            return errorResponse(404, "Not found");
        }
      }

      if (request.method === "POST") {
        switch (url.pathname) {
          case "/api/sso/list":
            return await handleSsoList(request, env);
          case "/api/sso/upsert":
            return await handleSsoUpsert(request, env);
          case "/api/sso/delete":
            return await handleSsoDelete(request, env);
          // Bot Config API
          case "/api/bot-config/list":
            return await handleBotConfigList(request, env);
          case "/api/bot-config/upsert":
            return await handleBotConfigUpsert(request, env);
          case "/api/bot-config/delete":
            return await handleBotConfigDelete(request, env);
          // User Management API
          case "/api/users/list":
            return await handleUsersList(request, env);
          case "/api/users/invitations":
            return await handleInvitationsList(request, env);
          case "/api/users/invite":
            return await handleInviteUser(request, env);
          case "/api/users/invite/delete":
            return await handleDeleteInvitation(request, env);
          case "/api/users/delete":
            return await handleDeleteUser(request, env);
          default:
            return errorResponse(404, "Not found");
        }
      }

      return errorResponse(405, "Method not allowed");
    } catch (err) {
      console.error(JSON.stringify({
        event: "unhandled_error",
        method: request.method,
        path: url.pathname,
        error: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
      }));
      return errorResponse(
        500,
        err instanceof Error ? err.message : "Internal server error",
      );
    }
  },
};
