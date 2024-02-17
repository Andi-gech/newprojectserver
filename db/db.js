const { MongoClient } = require("mongodb");

async function connectToDatabase() {
  console.log('connecting to database')
  try {
    const client = await MongoClient.connect(
      "mongodb://localhost:27017",
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
