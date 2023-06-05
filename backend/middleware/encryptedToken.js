require("dotenv").config();

const sanitize = require("mongo-sanitize");

const encryptedToken = (token) => {
  try {
    // convert to array
    let splitToken = sanitize(token).split("");

    //down the characters by derived
    let mapped = splitToken.map((element) =>
      element == " "
        ? element
        : String.fromCharCode(
            element.charCodeAt(0) - parseInt(process.env.NUMBEROFCHARS)
          )
    );

    let encryptedToken = mapped.join(""); // result
    return encryptedToken;
  } catch (err) {}
};

module.exports = encryptedToken;
