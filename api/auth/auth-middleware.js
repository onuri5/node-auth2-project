const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const bcrypt = require("bcryptjs");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return next({ status: 401, message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next({
        status: 401,
        message: "Token invalid",
      });
    }

    req.decodedJwt = decoded;
    next();
  });
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedJwt.role !== role_name) {
    next({
      status: 403,
      message: "This is not for you",
    });
  } else {
    next();
  }
};

const checkUsernameExists = async (req, res, next) => {
  const { username, password } = req.body;

  const [user] = await Users.findBy({ username });

  if (user && bcrypt.compareSync(password, user.password)) {
    req.user = user;
    next();
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
};

const validateRoleName = (req, res, next) => {
  if (req.body.role_name === undefined || req.body.role_name === null) {
    req.body.role_name = "student";
  } else {
    req.body.role_name = req.body.role_name.trim();
  }

  if (req.body.role_name === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  }

  if (req.body.role_name.length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  }

  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
