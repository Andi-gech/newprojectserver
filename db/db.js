const mongoose = require('mongoose');

// Connection URL
const url = 'mongodb://127.0.0.1:27017/database';

// Function to establish the database connection
async function dbConn() {
    try {
      await mongoose.connect(url, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Connected to the database!');
    } catch (error) {
      console.error('Failed to connect to the database:', error);
      throw error;
    }
  }

// Export the dbConn function
module.exports = dbConn;