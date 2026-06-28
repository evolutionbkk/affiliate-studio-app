/**
 * Affiliate Studio — Backend
 * Full TikTok integration: Login Kit (OAuth 2.0) + Content Posting API
 *
 * Endpoints
 *   GET  /                  -> serve dashboard (public/index.html)
 *   GET  /auth/tiktok       -> start TikTok OAuth
 *   GET  /auth/callback     -> exchange code for access token
 *   GET  /api/me            -> logged-in creator info (avatar, name)
 *   GET  /api/logout        -> clear session
 *   GET  /api/products      -> product scanner data (commission / ads / trend scoring)
 *   POST /api/post          -> upload a video and (optionally) direct-post it to TikTok
 *   GET  /api/post/:id/status -> poll publish status
 *
 * Requires Node 18+ (built-in fetch). See README.md for setup.
 */

import express from "express";
import session from "express-session";
import multer from "multer";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB

const {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  BASE_URL = "http://localhost:3000",
  SESSION_SECRET = "change-me",
  PORT = 3000,
} = process.env;

const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = "user.info.basic,user.info.profile,video.upload,video.publish";

app.use(express.json());
app.use(express.static(__dirname));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

/* ---------------- helpers ---------------- */
function requireAuth(req, res, next) {
  if (!req.session.accessToken) return res.status(401).json({ error: "not_authenticated" });
  next();
}

async function tk(url, options = {}) {
  const r = await fetch(url, options);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: r.ok, status: r.status, data };
}

/* ---------------- OAuth (Login Kit) ---------------- */
// Step 1: send the creator to TikTok to authorize
app.get("/auth/tiktok", (req, res) => {
  const csrf = crypto.randomBytes(16).toString("hex");
  req.session.csrf = csrf;
  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    response_type: "code",
    scope: SCOPES,
    redirect_uri: REDIRECT_URI,
    state: csrf,
  });
  res.redirect(`https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`);
});

// Step 2: TikTok redirects back with ?code= ; exchange it for an access token
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || state !== req.session.csrf) return res.status(400).send("Invalid OAuth state.");

  const body = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    client_secret: TIKTOK_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: REDIRECT_URI,
  });

  const { ok, data } = await tk("https://open.tiktokapis.com/v2/oauth/token/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!ok || !data.access_token) {
    return res.status(400).send("Token exchange failed: " + JSON.stringify(data));
  }

  req.session.accessToken = data.access_token;
  req.session.openId = data.open_id;
  res.redirect("/?connected=1");
});

app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* ---------------- creator info ---------------- */
app.get("/api/me", requireAuth, async (req, res) => {
  const fields = "open_id,union_id,avatar_url,display_name,username";
  const { ok, data } = await tk(
    `https://open.tiktokapis.com/v2/user/info/?fields=${fields}`,
    { headers: { Authorization: `Bearer ${req.session.accessToken}` } }
  );
  if (!ok) return res.status(400).json(data);
  res.json(data.data?.user || {});
});

/* ---------------- Content Posting API ----------------
 * Direct-post a video using the push_by_file (FILE_UPLOAD) method:
 *   1) init  -> get publish_id + upload_url
 *   2) PUT raw video bytes to upload_url
 *   3) client polls /api/post/:id/status
 * Docs: https://developers.tiktok.com/doc/content-posting-api-reference-direct-post
 */
app.post("/api/post", requireAuth, upload.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "no_video_file" });
    const { caption = "", directPost = "true", privacy = "SELF_ONLY" } = req.body;

    const videoSize = req.file.size;
    const chunkSize = videoSize;            // single chunk (files <= 64MB can be one chunk)
    const totalChunks = 1;

    const initBody = {
      post_info: {
        title: caption,
        privacy_level: privacy,            // SELF_ONLY for unaudited apps; PUBLIC_TO_EVERYONE after audit
        disable_comment: false,
        disable_duet: false,
        disable_stitch: false,
      },
      source_info: {
        source: "FILE_UPLOAD",
        video_size: videoSize,
        chunk_size: chunkSize,
        total_chunk_count: totalChunks,
      },
    };

    // Direct post vs. upload-as-draft use different init endpoints
    const initUrl =
      directPost === "true"
        ? "https://open.tiktokapis.com/v2/post/publish/video/init/"
        : "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/";

    const init = await tk(initUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
        "Content-Type": "application/json; charset=UTF-8",
      },
      body: JSON.stringify(initBody),
    });

    if (!init.ok || !init.data.data?.upload_url) {
      return res.status(400).json({ step: "init", response: init.data });
    }

    const { publish_id, upload_url } = init.data.data;

    // Upload the raw bytes
    const put = await fetch(upload_url, {
      method: "PUT",
      headers: {
        "Content-Type": req.file.mimetype || "video/mp4",
        "Content-Range": `bytes 0-${videoSize - 1}/${videoSize}`,
      },
      body: req.file.buffer,
    });

    if (!put.ok) {
      const t = await put.text();
      return res.status(400).json({ step: "upload", status: put.status, body: t });
    }

    res.json({ ok: true, publish_id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Poll publish status
app.get("/api/post/:id/status", requireAuth, async (req, res) => {
  const { ok, data } = await tk("https://open.tiktokapis.com/v2/post/publish/status/fetch/", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${req.session.accessToken}`,
      "Content-Type": "application/json; charset=UTF-8",
    },
    body: JSON.stringify({ publish_id: req.params.id }),
  });
  if (!ok) return res.status(400).json(data);
  res.json(data.data || {});
});

/* ---------------- product scanner ----------------
 * In production these numbers would be pulled from TikTok Shop /
 * an ad-intelligence source. Here they are served from a curated list.
 */
const PRODUCTS = [
  { name: "เซรั่มวิตซีเข้มข้น", brand: "GLOWLAB", cat: "ความงาม", commission: 25, ads: 92, brand_aw: 78, trend: 95 },
  { name: "หูฟังไร้สาย Pro", brand: "SonicX", cat: "แกดเจ็ต", commission: 12, ads: 88, brand_aw: 90, trend: 82 },
  { name: "ครีมกันแดดซองเดียว", brand: "SunGuard", cat: "ความงาม", commission: 30, ads: 74, brand_aw: 65, trend: 88 },
  { name: "กระติกเก็บความเย็น 2L", brand: "IceMate", cat: "ไลฟ์สไตล์", commission: 18, ads: 60, brand_aw: 55, trend: 70 },
  { name: "อาหารเสริมคอลลาเจน", brand: "Viti+", cat: "สุขภาพ", commission: 35, ads: 95, brand_aw: 72, trend: 91 },
  { name: "รองเท้าวิ่งน้ำหนักเบา", brand: "AeroRun", cat: "แฟชั่น", commission: 15, ads: 80, brand_aw: 85, trend: 76 },
  { name: "หม้อทอดไร้น้ำมัน 5L", brand: "CookEasy", cat: "เครื่องใช้", commission: 10, ads: 85, brand_aw: 88, trend: 80 },
  { name: "ลิปแมตต์ติดทน", brand: "VELVET", cat: "ความงาม", commission: 28, ads: 70, brand_aw: 60, trend: 84 },
  { name: "พาวเวอร์แบงค์ 20000", brand: "VoltGo", cat: "แกดเจ็ต", commission: 14, ads: 66, brand_aw: 75, trend: 62 },
  { name: "ชุดเซตสกินแคร์ 5 ชิ้น", brand: "DermaPure", cat: "ความงาม", commission: 32, ads: 90, brand_aw: 68, trend: 89 },
  { name: "เสื้อโอเวอร์ไซส์", brand: "STREETKO", cat: "แฟชั่น", commission: 20, ads: 55, brand_aw: 50, trend: 73 },
  { name: "แปรงสีฟันไฟฟ้า", brand: "CleanMax", cat: "สุขภาพ", commission: 16, ads: 78, brand_aw: 70, trend: 66 },
].map((p) => ({
  ...p,
  score: Math.min(100, Math.round((p.commission / 35) * 100 * 0.35 + p.ads * 0.25 + p.brand_aw * 0.2 + p.trend * 0.2)),
}));

app.get("/api/products", (req, res) => res.json(PRODUCTS));

/* ---------------- start ---------------- */
app.listen(PORT, () => {
  console.log(`Affiliate Studio running at ${BASE_URL} (port ${PORT})`);
  if (!TIKTOK_CLIENT_KEY) console.warn("⚠️  TIKTOK_CLIENT_KEY not set — see .env.example");
});
