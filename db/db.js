const mongoose = require('mongoose');

// Connection URL
const url = 'mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority';

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