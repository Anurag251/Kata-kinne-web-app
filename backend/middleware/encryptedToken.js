require("dotenv").config();
const crypto = require("crypto");

const algorithm = "aes-256-gcm";
const COOKIE_ENCRYPTION_KEY = process.env.COOKIE_ENCRYPTION_KEY;
const iv = crypto.randomBytes(12); // Generate a random initialization vector

// Encrypt a token
const encryptedToken = (token) => {
  const cipher = crypto.createCipheriv(
    algorithm,
    Buffer.from(COOKIE_ENCRYPTION_KEY, "hex"),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("hex");
};

module.exports = encryptedToken;
