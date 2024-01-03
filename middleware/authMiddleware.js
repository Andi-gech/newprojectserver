// middleware/authMiddleware.js
function isAuthenticated(req, res, next) {
    // Check if user is authenticated
    if (req.session.authenticated) {
      next();
    } else {
      
      res.status(401).json({ message: 'Unauthorized' });
    }
  }
  
  module.exports = isAuthenticated;