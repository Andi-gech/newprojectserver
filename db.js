const { MongoClient } = require("mongodb");

async function connectToDatabase() {
  try {
    const client = await MongoClient.connect(
      "mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority",
      { useUnifiedTopology: true }
    );
    return client.db("Mydatabase");
  } catch (error) {
    throw new Error(`Failed to connect to the database: ${error.message}`);
  }
}

module.exports = {
  connectToDatabase,
};
