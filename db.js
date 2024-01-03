const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');

async function connectDatabase() {
  try {
    // Mongoose connection
    await mongoose.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    const mongoUrl = 'mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority';

    // MongoDB native driver connection
    const client = new MongoClient(mongoUrl, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    await client.connect();
    const db = client.db();

    const mongoStore = MongoStore.create({
      mongoUrl: mongoUrl, // MongoDB connection URL
      ttl: 60 * 60, // Optional: session TTL in seconds
      client, // Pass the MongoDB native client to the MongoStore instance
    });

    // Return the Mongoose connection, MongoDB native client, and the MongoStore instance
    return { mongooseConnection: mongoose.connection, client, store: mongoStore };
  } catch (error) {
    console.error('Error connecting to the MongoDB database:', error);
    throw error;
  }
}

module.exports = connectDatabase;