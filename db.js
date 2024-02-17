const { MongoClient } = require("mongodb");

async function connectToDatabase() {

  try {
    console.log('connecting to database')
    const client = await MongoClient.connect(
      "mongodb://localhost:27017",
      { useUnifiedTopology: true }
    );
    return client.db("Mydatabase");
  } catch (error) {
    throw new Error(`Failed to connect to the databases: ${error.message}`);
  }
}

module.exports = {
  connectToDatabase,
};
