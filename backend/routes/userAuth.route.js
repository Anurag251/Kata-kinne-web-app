require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const sanitize = require("mongo-sanitize");

const router = express.Router();

const User = mongoose.model("User");
const UserVerificationCode = mongoose.model("UserVerificationCode");
const UserRefreshToken = mongoose.model("UserRefreshToken");

const encryptedToken = require("../middleware/encryptedToken");
const generateAccessToken = require("../middleware/generateAccessToken");

router.post("/signup", async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const email = sanitize(req.body.email);
    const password = sanitize(req.body.password);
    const confirmPassword = sanitize(req.body.confirmPassword);
    const otpCode = sanitize(req.body.otpCode);

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({
        status: false,
        message: "Invalid inputs. Please fill them in.",
      });
    }

    if (name.length < 3) {
      return res.status(400).json({
        status: false,
        message: "Name must be at least 3 characters long.",
      });
    }

    if (password === "" || confirmPassword === "") {
      return res.status(400).json({
        status: false,
        message: "Password field is empty.",
      });
    }

    if (password.length < 8 || confirmPassword.length < 8) {
      return res.status(400).json({
        status: false,
        message: "Password mmust be at least 8 characters long.",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        status: false,
        message: "Passwords didn't match.",
      });
    }

    const user = await User.findOne({ email });

    if (user !== null) {
      return res.status(200).json({
        status: false,
        message: "User already exists.",
      });
    }

    // if otp code exists
    if (typeof otpCode !== "undefined") {
      const removingUserVerificationCode =
        await UserVerificationCode.findOneAndRemove({
          email: email,
          code: parseInt(otpCode),
        });

      if (!removingUserVerificationCode) {
        return res.status(200).json({
          status: false,
          message: "OTP code is incorrect.",
        });
      }

      //create a new user
      const user = new User({
        name: name,
        email: email,
        password: password,
      });

      //save the user
      const newUser = await user.save();

      //generate refresh token
      const rt = jwt.sign(
        {
          id: newUser._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
          expiresIn: "30d",
        }
      );

      //create a new refresh token
      const refreshToken = new UserRefreshToken({
        email,
        refreshToken: rt,
      });

      //save the refresh token
      const newRefreshToken = await refreshToken.save();

      //generate access token
      const accessToken = generateAccessToken({ id: newUser._id });

      //set refresh token in cookie
      res.cookie("rt", encryptedToken(newRefreshToken.refreshToken), {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 30, //30 days
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
      });

      //send the response
      return res.status(200).json({
        status: true,
        message: "User created successfully.",
        token: accessToken,
      });
    } else {
      try {
        await UserVerificationCode.findOneAndRemove({ email });
        const generateOtpCode = Math.floor(100000 + Math.random() * 900000);

        const newOtpCode = new UserVerificationCode({
          code: generateOtpCode,
          email: email,
        });

        await newOtpCode.save();

        let transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false,
          requireTLS: true,
          auth: {
            user: process.env.EMAIL,
            pass: process.env.PASSWORD,
          },
        });

        //mailing option
        let mailOptions = {
          from: process.env.EMAIL,
          to: req.body.email,
          subject: "Verification Code",
          text: `Thanks for using our platform!\nThe code is ${generateOtpCode}`,
        };

        //send the mail
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            return res
              .status(400)
              .json({ status: false, message: "Email doesn't exists!" });
          }

          return res
            .status(200)
            .json({ status: true, message: "Code sent Successfully!" });
        });
      } catch (error) {
        return res.status(500).json({
          status: false,
          message: "Something went wrong.",
        });
      }
    }
  } catch (error) {
    return res.status(500).json({
      status: false,
      message: "Something went wrong.",
    });
  }
});

module.exports = router;
