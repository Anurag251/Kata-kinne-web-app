const mongoose = require("mongoose");
const userRefreshTokenSchema = new mongoose.Schema({
  refreshToken: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    default: Date.now(),
    index: {
      expires: "30d",
    },
  },
});

mongoose.model("UserRefreshToken", userRefreshTokenSchema);
