import crypto from "crypto";

const COOKIE_NAME = "wr_session";

function getEnvInt(name, def) {
  const v = parseInt(process.env[name] || "", 10);
  return Number.isFinite(v) ? v : def;
}

const MAX_CLICKS = getEnvInt("MAX_CLICKS", 3);

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

function sign(payload) {
  const secret = process.env.TOKEN_SECRET || "dev-secret";
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig  = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const cookie = req.headers.cookie || "";
  const token = cookie.split(/;\s*/).find(c => c.startsWith(COOKIE_NAME+"="))?.split("=")[1];
  const sess = verify(token);
  if (!sess) return res.status(400).send("Session invalid");

  // 累計點擊
  let clicks = (sess.clicks|0) + 1;
  if (clicks > MAX_CLICKS + 20) clicks = MAX_CLICKS + 20; // 上限防爆

  const next = { startAt: sess.startAt, clicks };
  const nextToken = sign(next);
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=${nextToken}; HttpOnly; Path=/; SameSite=Lax`);
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ clicks });
}
