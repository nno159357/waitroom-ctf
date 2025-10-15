import crypto from "crypto";

const COOKIE_NAME = "wr_session";

function getEnvInt(name, def) {
  const v = parseInt(process.env[name] || "", 10);
  return Number.isFinite(v) ? v : def;
}

const FLAG_READY_SECS = getEnvInt("FLAG_READY_SECS", 3600);
const AUTO_CLOSE_SECS = getEnvInt("AUTO_CLOSE_SECS", 1800);
const MAX_CLICKS      = getEnvInt("MAX_CLICKS", 3);

function sign(payload) {
  const secret = process.env.TOKEN_SECRET || "dev-secret";
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig  = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const startAt = Math.floor(Date.now() / 1000);
  const clicks = 0;
  const token = sign({ startAt, clicks });

  // HttpOnly + SameSite，可視需要加 secure
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=Lax`);
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ startAt, clicks, FLAG_READY_SECS, AUTO_CLOSE_SECS, MAX_CLICKS });
}
