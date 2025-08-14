const jwt = require('jsonwebtoken');
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('FATAL_ERROR: JWT_SECRET is not defined in the .env file');
}
exports.generateToken = (payload, expiresIn) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
};
exports.generatePasswordResetToken = (payload, secret,expiresIn = '15m') => {
  return jwt.sign(payload, secret, { expiresIn });
};
exports.verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};;

exports.verifyAccessJWT = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};
exports.generateResetToken = (userId, email) => {
  if (!userId || !email) {
    throw new Error('User ID and email are required to generate a token');
  }

  return jwt.sign(
    { userId, email }, 
    process.env.JWT_SECRET, 
    { expiresIn: '1h' } 
  );
};

