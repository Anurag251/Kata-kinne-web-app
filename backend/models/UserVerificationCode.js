const mongoose = require("mongoose");

//mongoose schema
const UserVerificationCodeSchema = new mongoose.Schema({
  code: {
    type: Number,
    required: true,
    maxlength: [10, "Code can't be more than 10 characters"],
  },
  email: {
    type: String,
    required: true,
    maxlength: [50, "Email can't be more than 50 characters."],
  },
  expiresAt: {
    type: Date,
    default: Date.now(),
    index: {
      expires: "5m",
    },
  },
});

mongoose.model("UserVerificationCode", UserVerificationCodeSchema);
