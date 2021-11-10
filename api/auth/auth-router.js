const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");
const bcrypt = require("bcryptjs");
const { BCRYPT_ROUNDS } = require("../secrets/index");
const tokenBuilder = require("./token-builder");

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;

  const rounds = BCRYPT_ROUNDS;
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;

  Users.add(user)
    .then(([newUser]) => {
      newUser.role_name = user.role_name;
      res.status(201).json(newUser);
    })
    .catch((err) => {
      next({ status: 500, message: err });
    });
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  const { username, password } = req.body;

  try {
    const token = tokenBuilder(req.user);
    res.status(200).json({ message: `${req.user.username} is back!`, token });
  } catch {
    res.status(500);
  }
});

module.exports = router;
