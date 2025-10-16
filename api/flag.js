export const config = { runtime: 'nodejs' };

import crypto from "crypto";

const COOKIE_NAME = "wr_session";

function getEnvInt(name, def) {
  const v = parseInt(process.env[name] || "", 10);
  return Number.isFinite(v) ? v : def;
}

const FLAG_READY_SECS = getEnvInt("FLAG_READY_SECS", 3600);
const AUTO_CLOSE_SECS = getEnvInt("AUTO_CLOSE_SECS", 1800);
const MAX_CLICKS      = getEnvInt("MAX_CLICKS", 3);
const FLAG_TEXT       = process.env.FLAG_TEXT || "FLAG{patient_is_power}";

function verify(token) {
  if (!token) return null;
  const secret = process.env.TOKEN_SECRET || "dev-secret"; // ← B: 弱金鑰
  const [data, sig] = String(token).split(".");
  const expect = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  if (sig !== expect) return null;
  try {
    return JSON.parse(Buffer.from(data, "base64url").toString());
  } catch { return null; }
}

/** A: 從隱藏 header 讀「現在時間」。另外 x-debug-mode=1 代表開啟 debug（略過關站判定） */
function pickDebugNow(req) {
  const raw = (req.headers["x-debug-now"] || req.headers["x-now"]);
  if (!raw) return null;
  const v = parseInt(Array.isArray(raw) ? raw[0] : raw, 10);
  return Number.isFinite(v) && v > 0 ? v : null;
}
function isDebugMode(req) {
  const raw = req.headers["x-debug-mode"];
  if (!raw) return false;
  const v = (Array.isArray(raw) ? raw[0] : raw).toString().trim();
  return v === "1" || v.toLowerCase() === "true";
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const cookie = req.headers.cookie || "";
  const token = cookie.split(/;\s*/).find(c => c.startsWith(COOKIE_NAME + "="))?.split("=")[1];
  const sess = verify(token);
  if (!sess) return res.status(400).send("Session invalid");

  // A: 若帶了 x-debug-now，用它當「現在時間」
  const debugNow = pickDebugNow(req);
  const debugOn  = isDebugMode(req) || debugNow !== null;
  const nowSec   = (debugNow ?? Math.floor(Date.now() / 1000));

  const elapsed = nowSec - (sess.startAt | 0);

  // （一般情況下要檢查是否關站；但 debug 模式略過）
  if (!debugOn && AUTO_CLOSE_SECS > 0 && elapsed >= AUTO_CLOSE_SECS) {
    return res.status(403).send("Timeout closed");
  }

  // 點擊次數仍要檢查（可用 B 偽造 cookie 將 clicks 設低）
  if ((sess.clicks | 0) > MAX_CLICKS) {
    return res.status(403).send("Too many clicks");
  }

  if (elapsed < FLAG_READY_SECS) {
    return res.status(400).send("Not ready");
  }

  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ flag: FLAG_TEXT });
}
