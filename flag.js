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
  const secret = process.env.TOKEN_SECRET || "dev-secret";
  const [data, sig] = String(token).split(".");
  const expect = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  if (sig !== expect) return null;
  try {
    return JSON.parse(Buffer.from(data, "base64url").toString());
  } catch { return null; }
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const cookie = req.headers.cookie || "";
  const token = cookie.split(/;\s*/).find(c => c.startsWith(COOKIE_NAME+"="))?.split("=")[1];
  const sess = verify(token);
  if (!sess) return res.status(400).send("Session invalid");

  const now = Math.floor(Date.now()/1000);
  const elapsed = now - (sess.startAt|0);

  // 判定條件（都以伺服器為準）
  if (sess.clicks > MAX_CLICKS) return res.status(403).send("Too many clicks");
  if (elapsed >= AUTO_CLOSE_SECS && AUTO_CLOSE_SECS > 0) return res.status(403).send("Timeout closed");
  if (elapsed < FLAG_READY_SECS) return res.status(400).send("Not ready");

  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ flag: FLAG_TEXT });
}
