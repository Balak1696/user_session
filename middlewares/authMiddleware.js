// middleware/authenticateToken.js
const jwtHelper = require('../utils/jwtHelper');
const { Session } = require('../models');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer <token>"

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // 1. Verify the JWT signature and expiration
    const decoded = jwtHelper.verifyToken(token);

    // 2. Verify that the session is still active in the database
    const session = await Session.findOne({ where: { token, userId: decoded.id } });
    if (!session) {
      return res.status(403).json({ message: 'Session invalid. Please log in again.' });
    }

    // Attach user information to the request object for use in subsequent controllers
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Token has expired. Please log in again.' });
    }
    return res.status(403).json({ message: 'Invalid token.' });
  }
};

module.exports = { authenticateToken };