require("dotenv").config();

const jwt = require("jsonwebtoken");
const encryptedToken = require("./encryptedToken");

function generateAccessToken(user) {
  return encryptedToken(
    jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "8m" })
  );
}

module.exports = generateAccessToken;
