const mongoose = require('mongoose');

// Define the user schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  permission: { type: String,default:"editor",required:true },
  session: {
    sessionId: { type: String },
    expiresAt: { type: Date },
    createdAt: { type: Date, default: Date.now },
    ipAddress: { type: String },
    userAgent: { type: String },
  },
});

// Create the User model using the user schema
const User = mongoose.model('User', userSchema);

// Export the User model
module.exports = User;