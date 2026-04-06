import { handleLoginPage } from "./handlers/login-page";
import { handleAuthLogin } from "./handlers/login-api";
import { handleGoogleRedirect } from "./handlers/google-redirect";
import { handleGoogleCallback } from "./handlers/google-callback";
import { handleLineworksRedirect } from "./handlers/lineworks-redirect";
import { handleLineworksCallback } from "./handlers/lineworks-callback";
import { handleAdminSsoPage, handleAdminSsoCallback } from "./handlers/admin-sso";
import { handleAdminUsersPage, handleAdminUsersCallback } from "./handlers/admin-users";
import { handleSsoList, handleSsoUpsert, handleSsoDelete } from "./handlers/api-sso";
import { handleBotConfigList, handleBotConfigUpsert, handleBotConfigDelete } from "./handlers/api-bot-config";
import { handleWoffAuth, handleWoffConfig } from "./handlers/woff-auth";
import { handleMyOrgs } from "./handlers/api-my-orgs";
import { handleSwitchOrg } from "./handlers/api-switch-org";
import {
  handleRichMenuList, handleRichMenuCreate, handleRichMenuDelete,
  handleRichMenuImageUpload, handleRichMenuDefaultSet, handleRichMenuDefaultDelete,
} from "./handlers/api-rich-menu";
import { handleAdminRichMenuPage, handleAdminRichMenuCallback } from "./handlers/admin-rich-menu";
import { handleTopPage } from "./handlers/top-page";
import { handleHealthProxy } from "./handlers/health";
import {
  handleUsersList, handleInvitationsList, handleInviteUser,
  handleDeleteInvitation, handleDeleteUser,
} from "./handlers/api-users";
import { handleLogout } from "./handlers/logout";
import { handleJoinPage } from "./handlers/join-page";
import { handleJoinDone } from "./handlers/join-callback";
import { handleRedirect } from "./handlers/redirect";
import { handleAdminRequestsPage, handleAdminRequestsCallback } from "./handlers/admin-requests";
import {
  handleAccessRequestCreate, handleAccessRequestList,
  handleAccessRequestApprove, handleAccessRequestDecline,
} from "./handlers/api-access-requests";
import { corsPreflight } from "./lib/errors";

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
        // Dynamic path: /join/:slug and /join/:slug/done
        if (url.pathname.startsWith("/join/")) {
          const parts = url.pathname.split("/");
          const slug = parts[2];
          if (parts.length === 3 && slug) {
            return await handleJoinPage(request, env, slug);
          }
          if (parts.length === 4 && parts[3] === "done" && slug) {
            return handleJoinDone(slug);
          }
          return errorResponse(404, "Not found");
        }

        switch (url.pathname) {
          case "/api/health":
            return await handleHealthProxy(env);
          case "/login":
            return await handleLoginPage(request, env);
          case "/top":
            return await handleTopPage(request, env);
          case "/oauth/google/redirect":
            return await handleGoogleRedirect(request, env);
          case "/oauth/google/callback":
            return await handleGoogleCallback(request, env);
          case "/oauth/lineworks/redirect":
            return await handleLineworksRedirect(request, env);
          case "/oauth/lineworks/callback":
            return await handleLineworksCallback(request, env);
          case "/auth/woff-config":
            return await handleWoffConfig(request, env);
          case "/admin/sso":
            return await handleAdminSsoPage(request, env);
          case "/admin/sso/callback":
            return await handleAdminSsoCallback();
          case "/admin/users":
            return await handleAdminUsersPage(request, env);
          case "/admin/users/callback":
            return await handleAdminUsersCallback();
          case "/admin/rich-menu":
            return await handleAdminRichMenuPage(request, env);
          case "/admin/rich-menu/callback":
            return await handleAdminRichMenuCallback();
          case "/admin/requests":
            return await handleAdminRequestsPage(request, env);
          case "/admin/requests/callback":
            return await handleAdminRequestsCallback();
          case "/redirect":
            return await handleRedirect(request, env);
          case "/logout":
            return await handleLogout(request, env);
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
          // WOFF Auth
          case "/auth/woff":
            return await handleWoffAuth(request, env);
          // Password login
          case "/auth/login":
            return await handleAuthLogin(request, env);
          // Rich Menu API
          case "/api/richmenu/list":
            return await handleRichMenuList(request, env);
          case "/api/richmenu/create":
            return await handleRichMenuCreate(request, env);
          case "/api/richmenu/delete":
            return await handleRichMenuDelete(request, env);
          case "/api/richmenu/image":
            return await handleRichMenuImageUpload(request, env);
          case "/api/richmenu/default/set":
            return await handleRichMenuDefaultSet(request, env);
          case "/api/richmenu/default/delete":
            return await handleRichMenuDefaultDelete(request, env);
          // Access Request API
          case "/api/access-requests/create":
            return await handleAccessRequestCreate(request, env);
          case "/api/access-requests/list":
            return await handleAccessRequestList(request, env);
          case "/api/access-requests/approve":
            return await handleAccessRequestApprove(request, env);
          case "/api/access-requests/decline":
            return await handleAccessRequestDecline(request, env);
          // Organization API
          case "/api/switch-org":
            return await handleSwitchOrg(request, env);
          case "/api/my-orgs":
            return await handleMyOrgs(request, env);
          default:
            return errorResponse(404, "Not found");
        }
      }

      // CORS preflight
      if (request.method === "OPTIONS") {
        return corsPreflight();
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
