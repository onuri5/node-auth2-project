const jwt = require("jsonwebtoken");
const { TOKEN_SECRET } = require("../secrets/index");

module.exports = function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name,
  };
  const options = {
    expiresIn: "1d",
    
  };

  return jwt.sign(payload, TOKEN_SECRET, options);
};
