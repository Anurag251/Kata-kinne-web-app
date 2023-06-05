require("dotenv").config();

const express = require("express");
const next = require("next");
const bodyParser = require("body-parser");
const csrf = require("csurf");
const helmet = require("helmet");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

// const cluster = require("cluster");
// const os = require("os");

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();

// const numCpu = os.cpus().length;
const PORT = 8000;

// //if the cluster is master
// if (cluster.isMaster) {
//   for (let i = 0; i < numCpu; i++) {
//     cluster.fork();
//   }

//   //if worker dies or is killed
//   cluster.on("exit", (worker, code, signal) => {
//     cluster.fork();
//   });
// } else {
app.prepare().then(() => {
  const server = express();

  //parse json
  server.use(bodyParser.json());

  //cookie configuration
  server.use(
    cookieParser({
      cookie: {
        sameSite: "strict",
        httpOnly: true,
        secure: process.env.HTTPS,
      },
    })
  );

  //   //csrf token
  //   server.use(
  //     csrf({
  //       cookie: {
  //         sameSite: "strict",
  //         httpOnly: true,
  //         secure: process.env.HTTPS,
  //       },
  //     })
  //   );

  //   // get csrf token
  //   server.get("/api/csrf", (req, res) => {
  //     return res.status(200).json({ status: true, csrfToken: req.csrfToken() });
  //   });

  //helmet
  server.use(helmet());

  //   //prevent ddos and bruteforce
  //   server.use(
  //     limitter({
  //       windowMs: 1000 * 60 * 10,
  //       max: 1000,
  //       message: {
  //         code: 429,
  //         message: "Too many requests, Please try again later.",
  //         status: false,
  //       },
  //     })
  //   );

  //connect to mongodb
  mongoose.connect(process.env.URI);

  //on connection
  mongoose.connection.on("connected", () => {
    console.log("connected to DB.");
  });

  //on error
  mongoose.connection.on("error", () => {
    console.log("Failed to connect to the DB.");
  });

  //models
  require("./models/User");
  require("./models/UserVerificationCode");
  require("./models/UserRefreshToken");

  //routes
  const userAuthRoutes = require("./routes/userAuth.route");

  //limitter for routes
  const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: "Too many requests from this IP, please try again later.",
  });

  //call routes
  server.use("/auth/", authLimiter);
  server.use("/auth/", userAuthRoutes);

  server.all("*", (req, res) => {
    return handle(req, res);
  });

  server.listen(PORT, (err) => {
    if (err) throw err;
    console.log(`> Ready on http://localhost:${PORT}`, process.pid);
  });
});
// .catch((ex) => {
//   process.exit(1);
// });
// }
