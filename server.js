require("dotenv").config();

const express = require("express");
const path = require("path");
const dns = require("node:dns").promises;
const crypto = require("node:crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = Number(process.env.PORT || 3000);
app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const allowedDomains = new Set(["gmail.com", "googlemail.com"]);
const challenges = new Map(); // Prototype only: lost when server restarts.
const sendCooldowns = new Map();
const ipBuckets = new Map();

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return email.length <= 254 &&
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(email);
}

function emailDomain(email) {
  return email.split("@").pop().toLowerCase();
}

function ipRateLimit(req, res, next) {
  // Basic in-memory limit for a prototype; use a shared store and trusted
  // proxy configuration for production.
  const key = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const max = 20;
  let bucket = ipBuckets.get(key);

  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
  }
  bucket.count += 1;
  ipBuckets.set(key, bucket);

  if (bucket.count > max) {
    return res.status(429).json({ error: "Terlalu banyak permintaan. Coba lagi nanti." });
  }
  next();
}

app.use("/api", ipRateLimit);

app.post("/api/check-domain", async (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  if (!validEmail(email)) {
    return res.status(400).json({ error: "Format email tidak valid." });
  }
  if (!allowedDomains.has(emailDomain(email))) {
    return res.status(400).json({ error: "Prototipe ini hanya mendukung alamat @gmail.com atau @googlemail.com." });
  }

  try {
    const records = await dns.resolveMx(emailDomain(email));
    const hasMx = Array.isArray(records) && records.length > 0;
    return res.json({
      format: "VALID",
      domainMx: hasMx ? "FOUND" : "NOT_FOUND",
      note: "MX hanya menunjukkan konfigurasi penerimaan email domain, bukan bahwa kotak masuk atau akun ini terdaftar."
    });
  } catch (err) {
    // DNS errors do not prove that the mailbox is absent.
    return res.json({
      format: "VALID",
      domainMx: "UNKNOWN",
      note: "DNS tidak dapat dipastikan saat ini. Ini bukan bukti bahwa akun tidak ada."
    });
  }
});

function createTransporter() {
  const required = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM"];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length) {
    throw new Error("SMTP belum dikonfigurasi di file .env.");
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

app.post("/api/send-code", async (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  if (!validEmail(email) || !allowedDomains.has(emailDomain(email))) {
    return res.status(400).json({ error: "Masukkan alamat Gmail dengan format yang valid." });
  }

  const now = Date.now();
  const lastSent = sendCooldowns.get(email) || 0;
  if (now - lastSent < 60 * 1000) {
    return res.status(429).json({ error: "Tunggu 60 detik sebelum meminta kode baru." });
  }

  let transporter;
  try {
    transporter = createTransporter();
  } catch (err) {
    return res.status(503).json({
      error: "Pengiriman kode belum dikonfigurasi. Isi pengaturan SMTP di .env terlebih dahulu."
    });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto.createHash("sha256").update(salt + code).digest("hex");

  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "Kode verifikasi Gmail Checker",
      text: `Kode verifikasi Anda: ${code}\nKode berlaku selama 10 menit. Jika Anda tidak meminta kode ini, abaikan email ini.`,
      html: `<p>Kode verifikasi Anda:</p><p style="font-size:28px;font-weight:bold;letter-spacing:5px">${code}</p><p>Kode berlaku selama 10 menit. Jika Anda tidak meminta kode ini, abaikan email ini.</p>`
    });

    challenges.set(email, {
      salt,
      digest,
      expiresAt: now + 10 * 60 * 1000,
      attempts: 0
    });
    sendCooldowns.set(email, now);
    return res.json({
      sent: true,
      message: "Permintaan pengiriman berhasil diproses. Masukkan kode yang diterima untuk membuktikan akses inbox."
    });
  } catch (err) {
    // Do not return raw SMTP errors; they may contain sensitive information.
    return res.status(502).json({
      error: "Kode belum berhasil dikirim. Periksa konfigurasi layanan email dan coba lagi nanti."
    });
  }
});

app.post("/api/verify-code", (req, res) => {
  const email = normalizeEmail(req.body && req.body.email);
  const code = String((req.body && req.body.code) || "").trim();

  if (!validEmail(email) || !allowedDomains.has(emailDomain(email)) || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Email atau format kode tidak valid." });
  }

  const challenge = challenges.get(email);
  if (!challenge) {
    return res.status(400).json({ error: "Tidak ada kode aktif. Minta kode baru terlebih dahulu." });
  }
  if (Date.now() > challenge.expiresAt) {
    challenges.delete(email);
    return res.status(400).json({ error: "Kode kedaluwarsa. Minta kode baru." });
  }
  if (challenge.attempts >= 5) {
    challenges.delete(email);
    return res.status(429).json({ error: "Batas percobaan tercapai. Minta kode baru nanti." });
  }

  challenge.attempts += 1;
  const submitted = crypto.createHash("sha256").update(challenge.salt + code).digest("hex");
  const matches = crypto.timingSafeEqual(Buffer.from(submitted, "hex"), Buffer.from(challenge.digest, "hex"));

  if (!matches) {
    return res.status(400).json({ error: "Kode salah. Periksa kembali email Anda." });
  }

  challenges.delete(email);
  return res.json({
    status: "INBOX_VERIFIED",
    message: "Kode benar. Akses ke inbox email ini berhasil diverifikasi pada saat ini.",
    limitation: "Ini tidak membuktikan status akun Google secara keseluruhan atau apakah akun sedang login di perangkat tertentu."
  });
});

app.listen(PORT, () => {
  console.log(`Gmail Checker berjalan di http://localhost:${PORT}`);
});
                                 
