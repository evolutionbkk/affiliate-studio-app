/**
 * Affiliate Studio — Backend
 * Full TikTok integration: Login Kit (OAuth 2.0) + Content Posting API
 *
 * Endpoints
 *   GET  /                  -> serve dashboard (index.html)
 *   GET  /auth/tiktok       -> start TikTok OAuth
 *   GET  /auth/callback     -> exchange code for access token
 *   GET  /api/me            -> logged-in creator info (avatar, name)
 *   GET  /api/logout        -> clear session
 *   GET  /api/products      -> product scanner data (commission / ads / trend scoring)
 *   GET  /api/radar         -> Market Radar data (trend7d / ad intensity / saturation / Opportunity Score)
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

/* ===================================================================
 *  MARKET DATA — single source of truth
 *  Both the product scanner and Market Radar read from this one list.
 *  Each item carries the rich fields the Radar needs; the scanner just
 *  reads a projection of them. When the live data source is wired up
 *  (TikTok Creative Center Top Products, later Kalodata/FastMoss), only
 *  loadMarket() below needs to change — the API shapes stay the same.
 * =================================================================== */

// brand_aw = brand awareness (0-100), used by the scanner column "รู้จักแบรนด์"
const MARKET = [
  { name: "เซรั่มวิตซีเข้มข้น",            brand: "GLOWLAB",   cat: "ความงาม",   commission: 25, adIntensity: 92, saturation: 48, trend7d: 62,  brand_aw: 78, sold: 18400, price: 390,  rating: 4.8 },
  { name: "ครีมกันแดดซองเดียว",          brand: "SunGuard",  cat: "ความงาม",   commission: 30, adIntensity: 74, saturation: 35, trend7d: 88,  brand_aw: 65, sold: 12600, price: 120,  rating: 4.7 },
  { name: "อาหารเสริมคอลลาเจน",          brand: "Viti+",     cat: "สุขภาพ",    commission: 35, adIntensity: 95, saturation: 70, trend7d: 41,  brand_aw: 72, sold: 9800,  price: 590,  rating: 4.6 },
  { name: "ลิปออยล์เปลี่ยนสี",            brand: "VELVET",    cat: "ความงาม",   commission: 28, adIntensity: 70, saturation: 30, trend7d: 95,  brand_aw: 60, sold: 15200, price: 180,  rating: 4.9 },
  { name: "หูฟังไร้สาย Pro",             brand: "SonicX",    cat: "แกดเจ็ต",   commission: 12, adIntensity: 88, saturation: 90, trend7d: 18,  brand_aw: 90, sold: 7400,  price: 990,  rating: 4.5 },
  { name: "ไฟ Mood Light ตั้งโต๊ะ",       brand: "LumiGlow",  cat: "ไลฟ์สไตล์", commission: 22, adIntensity: 55, saturation: 25, trend7d: 120, brand_aw: 45, sold: 21000, price: 290,  rating: 4.8 },
  { name: "ชุดเซตสกินแคร์เกาหลี 5 ชิ้น",   brand: "DermaPure", cat: "ความงาม",   commission: 32, adIntensity: 90, saturation: 58, trend7d: 54,  brand_aw: 68, sold: 8900,  price: 790,  rating: 4.7 },
  { name: "หม้อทอดไร้น้ำมัน 5L",         brand: "CookEasy",  cat: "เครื่องใช้", commission: 10, adIntensity: 85, saturation: 88, trend7d: 8,   brand_aw: 88, sold: 6100,  price: 1290, rating: 4.6 },
  { name: "แปรงสีฟันไฟฟ้า",              brand: "CleanMax",  cat: "สุขภาพ",    commission: 16, adIntensity: 60, saturation: 72, trend7d: -12, brand_aw: 70, sold: 4300,  price: 450,  rating: 4.4 },
  { name: "กระติกเก็บความเย็น 2L",        brand: "IceMate",   cat: "ไลฟ์สไตล์", commission: 18, adIntensity: 48, saturation: 40, trend7d: 34,  brand_aw: 55, sold: 5600,  price: 350,  rating: 4.5 },
  { name: "รองเท้าวิ่งน้ำหนักเบา",         brand: "AeroRun",   cat: "แฟชั่น",    commission: 15, adIntensity: 80, saturation: 85, trend7d: -5,  brand_aw: 85, sold: 3900,  price: 1190, rating: 4.6 },
  { name: "มาส์กหน้าใส 10 แผ่น",         brand: "AquaVeil",  cat: "ความงาม",   commission: 33, adIntensity: 66, saturation: 33, trend7d: 77,  brand_aw: 58, sold: 13400, price: 230,  rating: 4.8 },
];

/* ---- scoring helpers (shared definitions) ---- */
const commissionScore = (c) => Math.min(100, Math.round((c / 35) * 100));
const trendScore = (t) => Math.max(0, Math.min(100, Math.round(50 + t * 0.5)));

// Opportunity Score = กระแส×0.3 + คอมมิชชั่น×0.3 + ความเข้มแอด×0.2 + (คู่แข่งน้อย)×0.2
function withScores(p) {
  const opp = Math.round(
    trendScore(p.trend7d) * 0.3 +
    commissionScore(p.commission) * 0.3 +
    p.adIntensity * 0.2 +
    (100 - p.saturation) * 0.2
  );
  return { ...p, opp, blueOcean: opp >= 75 && p.saturation < 50 };
}

/**
 * loadMarket() — the single seam for real data.
 * Today: returns the curated MARKET list. Later: fetch TikTok Creative
 * Center "Top Products" (free, best-effort), then merge Kalodata/FastMoss
 * fields, and return rows in the SAME shape as MARKET above.
 */
async function loadMarket() {
  // TODO: replace with live fetch; keep the returned object shape identical.
  return MARKET.map(withScores);
}

/* ---------------- product scanner ----------------
 * Scanner reads a projection of the shared market list.
 * "ads" = ad intensity, "trend" = normalised 0-100 trend score.
 */
app.get("/api/products", async (req, res) => {
  const market = await loadMarket();
  const products = market.map((p) => {
    const ads = p.adIntensity;
    const trend = trendScore(p.trend7d);
    const score = Math.min(
      100,
      Math.round((p.commission / 35) * 100 * 0.35 + ads * 0.25 + p.brand_aw * 0.2 + trend * 0.2)
    );
    return {
      name: p.name, brand: p.brand, cat: p.cat,
      commission: p.commission, ads, brand_aw: p.brand_aw, trend, score,
    };
  });
  res.json(products);
});

/* ---------------- Market Radar ----------------
 * Radar reads the full rich market list with Opportunity Score computed
 * server-side, so the dashboard tab and the (legacy) radar page agree.
 */
app.get("/api/radar", async (req, res) => {
  const market = await loadMarket();
  res.json({
    generatedAt: new Date().toISOString(),
    source: "sample", // -> "creative_center" / "kalodata" once wired up
    products: market,
  });
});

/* ---------------- start ---------------- */
app.listen(PORT, () => {
  console.log(`Affiliate Studio running at ${BASE_URL} (port ${PORT})`);
  if (!TIKTOK_CLIENT_KEY) console.warn("⚠️  TIKTOK_CLIENT_KEY not set — see .env.example");
});
