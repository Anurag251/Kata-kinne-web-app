require("dotenv").config();
const crypto = require("crypto");

const algorithm = "aes-256-gcm";
const COOKIE_ENCRYPTION_KEY = process.env.COOKIE_ENCRYPTION_KEY;

// Decrypt a token
const decryptedToken = (encryptedToken) => {
  const buffer = Buffer.from(encryptedToken, "hex");
  const iv = buffer.slice(0, 12);
  const tag = buffer.slice(12, 28);
  const encrypted = buffer.slice(28);

  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(COOKIE_ENCRYPTION_KEY, "hex"),
    iv
  );
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString("utf8");
};

module.exports = decryptedToken;
