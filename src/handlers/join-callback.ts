/**
 * Join callback handler: GET /join/:slug/done
 * Serves HTML page that reads JWT from fragment and calls CreateAccessRequest API
 */

import { renderJoinDonePage } from "../lib/join-html";

export function handleJoinDone(slug: string): Response {
  const html = renderJoinDonePage(slug);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
