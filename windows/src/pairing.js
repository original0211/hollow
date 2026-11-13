// Pairing payload logic (plan §3, M2-3 / NP-1114-07). Pure and testable:
// payload build/parse/validate for the three import forms, export builders,
// and QR pixel plumbing. Red-team correction 4 lives in the caller (main):
// NOTHING here writes to disk — parsing only produces data for the in-app
// confirmation step, and callers must never log the payload (PSK may ride
// inside).
import QRCode from "qrcode";
import jsQR from "jsqr";

export const LINK_PREFIX = "hollow://v1";
const MAX_PAYLOAD = 8192;

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
function unb64url(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error("invalid base64url");
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function validateWorkerUrl(u) {
  if (typeof u !== "string" || u.length > 512) throw new Error("worker url missing/too long");
  let parsed;
  try { parsed = new URL(u); } catch { throw new Error("worker url not a URL"); }
  if (parsed.protocol === "wss:") return u;
  if (parsed.protocol === "ws:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")) return u;
  throw new Error("worker url must be wss:// (ws:// only for localhost)");
}
function validateFields({ workerUrl, keyId, psk }) {
  const url = validateWorkerUrl(workerUrl);
  const kid = keyId === undefined || keyId === null ? 1 : keyId;
  if (!Number.isInteger(kid) || kid < 0 || kid > 255) throw new Error("keyId out of range");
  let pskBytes = null;
  if (psk !== undefined && psk !== null) {
    pskBytes = psk instanceof Uint8Array ? psk : unb64url(psk);
    if (pskBytes.length !== 32) throw new Error("psk must be 32 bytes");
  }
  return { workerUrl: url, keyId: kid, psk: pskBytes };
}

// ---- link form: hollow://v1?worker=<enc>&keyId=<n>&psk=<b64url, optional>
export function buildLink({ workerUrl, keyId = 1, psk = null }) {
  const v = validateFields({ workerUrl, keyId, psk });
  const q = new URLSearchParams({ worker: v.workerUrl, keyId: String(v.keyId) });
  if (v.psk) q.set("psk", b64url(v.psk));
  return `${LINK_PREFIX}?${q.toString()}`;
}
export function parseLink(text) {
  if (typeof text !== "string" || text.length > MAX_PAYLOAD) throw new Error("payload too large");
  const t = text.trim();
  if (!t.startsWith(LINK_PREFIX)) throw new Error("not a hollow://v1 link");
  const u = new URL(t.replace(/^hollow:/, "http:")); // URL parser needs a known scheme shape
  const worker = u.searchParams.get("worker");
  const psk = u.searchParams.get("psk");
  const keyId = u.searchParams.get("keyId");
  return validateFields({ workerUrl: worker, keyId: keyId ? Number(keyId) : 1, psk });
}

// ---- file form: .hollow.json ----
export function buildExportObject({ workerUrl, keyId = 1, psk = null }) {
  const v = validateFields({ workerUrl, keyId, psk });
  const obj = { app: "hollow", version: 1, workerUrl: v.workerUrl, keyId: v.keyId };
  if (v.psk) obj.pskBase64 = Buffer.from(v.psk).toString("base64");
  return obj;
}
export function parseExportObject(text) {
  if (typeof text !== "string" || text.length > MAX_PAYLOAD) throw new Error("payload too large");
  let obj;
  try { obj = JSON.parse(text); } catch { throw new Error("not JSON"); }
  if (!obj || obj.app !== "hollow" || obj.version !== 1) throw new Error("not a hollow export file");
  let psk = null;
  if (obj.pskBase64 !== undefined) {
    if (typeof obj.pskBase64 !== "string" || !/^[A-Za-z0-9+/=]+$/.test(obj.pskBase64)) throw new Error("bad pskBase64");
    psk = new Uint8Array(Buffer.from(obj.pskBase64, "base64"));
  }
  return validateFields({ workerUrl: obj.workerUrl, keyId: obj.keyId, psk });
}

// Any import surface feeds through here: link, file, QR text, OS-open link.
export function parseAnyPayload(text) {
  if (typeof text !== "string") throw new Error("empty payload");
  const t = text.trim();
  if (t.startsWith(LINK_PREFIX)) return parseLink(t);
  if (t.startsWith("{")) return parseExportObject(t);
  throw new Error("unrecognized payload form");
}

// What the confirmation UI may show: never the PSK itself — only whether one
// rides along and the verifier it implies (V is the displayable pairing id).
export function previewOf(parsed, { currentPskExists, verifierOf }) {
  return {
    workerUrl: parsed.workerUrl,
    keyId: parsed.keyId,
    hasPsk: !!parsed.psk,
    pskVerifier: parsed.psk ? verifierOf(parsed.psk) : null,
    overwritesPsk: !!(parsed.psk && currentPskExists),
  };
}

// ---- QR ----
export async function qrDataUrl(text) {
  return QRCode.toDataURL(text, { margin: 2, width: 320, errorCorrectionLevel: "M" });
}
// Electron's nativeImage hands us BGRA bitmaps; jsQR wants RGBA.
export function bgraToRgba(buf) {
  const out = new Uint8ClampedArray(buf.length);
  for (let i = 0; i < buf.length; i += 4) {
    out[i] = buf[i + 2]; out[i + 1] = buf[i + 1]; out[i + 2] = buf[i]; out[i + 3] = buf[i + 3];
  }
  return out;
}
export function decodeQrFromPixels(rgba, width, height) {
  const res = jsQR(rgba, width, height);
  if (!res || !res.data) throw new Error("no QR code found in image");
  return res.data;
}
// For tests: render a QR into a raw RGBA pixel buffer without a canvas.
export function qrPixels(text, scale = 8) {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const size = qr.modules.size;
  const data = qr.modules.data;
  const quiet = 4;
  const dim = (size + quiet * 2) * scale;
  const rgba = new Uint8ClampedArray(dim * dim * 4).fill(255);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (!data[y * size + x]) continue;
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
      const px = ((y + quiet) * scale + dy) * dim + (x + quiet) * scale + dx;
      rgba[px * 4] = 0; rgba[px * 4 + 1] = 0; rgba[px * 4 + 2] = 0; rgba[px * 4 + 3] = 255;
    }
  }
  return { rgba, width: dim, height: dim };
}
