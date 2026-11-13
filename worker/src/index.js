// newproto worker — minimal shell (M1 scaffold, NP-1113-02).
// Only version + health endpoints. No protocol logic yet:
// protocol implementation lands after spec v0.1 passes review.

export const NAME = "newproto-worker";
export const VERSION = "0.0.1";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({ name: NAME, version: VERSION, status: "ok" });
    }
    if (url.pathname === "/" || url.pathname === "/version") {
      return json({ name: NAME, version: VERSION });
    }
    return json({ error: "not_found" }, 404);
  },
};
