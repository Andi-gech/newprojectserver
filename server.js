const express = require('express');
const dbConn = require('./db/db.js');
const session = require('express-session');
const { MongoClient, MongoError } = require('mongodb');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const app = express();
const User = require('./models/Users');
const MainData = require('./models/Data');
const multer = require('multer');
const csv = require('csv-parser');

const fs = require('fs');
// const upload = multer({ dest: 'uploads/' });
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const path = require('path');
const ExcelJS = require('exceljs');
const cors=require('cors')
const streamifier = require('streamifier');
const fastcsv = require('fast-csv');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const stream = require('stream');


// Call the connectToDatabase function to establish the connection
dbConn()
  .then(() => {
    app.listen(9050, () => {
      console.log('Server running on port 9000');
      
    });
  })
  .catch((error) => {
    console.error('Failed to establish database connection:', error);
  });
 
// Generate a random secret key
const secretKey = crypto.randomBytes(64).toString('hex');
const storage = multer.memoryStorage(); // Store the file in memory
const upload = multer({ storage: storage });


const currentTime = new Date();
const expirationTime = new Date(currentTime.getTime() + 60 * 60 * 1000);

// Middleware'
app.use(cors())
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


const isAuthenticated = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const [tokenType, token] = authHeader.split(' ');

  if (!tokenType || tokenType.toLowerCase() !== 'jwt' || !token) {
    return res.status(401).json({ message: 'Invalid token type or format' });
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, '1q2w3e4r5t');

    // Attach user information to the request object
    req.user = decoded;

    next();
  } catch (error) {
    console.error('Error during authentication:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
};


// Middleware to check role
const canEdit = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    const loggedInUserPermission = req.session.permission;
    if (loggedInUserPermission !== 'admin' || loggedInUserPermission !== 'editor') {
      return res.status(403).json({ message: 'Only admins and editors have this privilege' });
    }else {
      next();
    }
  }
};

// Middleware to verify admin role
const isAdmin = (req, res, next) => {
  if (req.session && req.session.authenticated) {

    const loggedInUserPermission = req.session.permission;
    // Check if the logged-in user has admin permissions
    if (loggedInUserPermission !== 'admin') {
      return res.status(403).json({ message: 'Only admins has this privilege' });
    }
    else{
      next();
    }
  }
};

// Sign-in route
app.post('/auth/signin', async (req, res) => {
  const { username, password } = req.body;
  console.log(username,password)

  try {
    // Find the user by username in the database
    const user = await User.findOne({ username });

    if (user) {
    
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
      
        const accessToken = jwt.sign(
          {
            username: user.username,
            permission: user.permission,
          },
          '1q2w3e4r5t', 
          { expiresIn: 86400 } 
        );

        // Generate a refresh token
        const refreshToken = jwt.sign(
          { username: user.username },
          'your-refresh-secret-key', 
          { expiresIn: 432000 } 
        );

        res.json({
          accessToken,
          expiresIn: 86400,
          tokenType: 'Jwt',
          authUserState: 'authenticated',
          refreshToken,
          refreshTokenExpireIn: 432000,
        });
      } else {
        res.status(401).json({ message: 'Invalid password' });
      }
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error during sign-in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token is missing' });
  }

  jwt.verify(refreshToken, 'your-refresh-secret-key', async (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    // Check if the user exists in the database
    const user = await User.findOne({ username: decoded.username });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a new access token
    const newAccessToken = jwt.sign(
      {
        username: user.username,
        permission: user.permission,
      },
      '1q2w3e4r5t',
      { expiresIn: 86400 }
    );

    res.json({
      accessToken: newAccessToken,
      expiresIn: 86400,
      tokenType: 'Jwt',
      authUserState: 'authenticated',
    });
  });
});



// Sign-out route
app.post('/auth/signout', async (req, res) => {
  try {
    // Find the user by username in the database
    const user = await User.findOne({ username: req.session.username });
    console.log(req.session.username);
    if (user) {
      // Remove the session information from the user document
      user.session = null;
      await user.save();
    }

    req.session.destroy();
    res.clearCookie('connect.sid'); // Clear the session ID cookie
    res.json({ message: 'Sign-out successful' });
  } catch (error) {
    console.error('Error during sign-out:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Change password route
// Change password route
app.post('/auth/changepassword', isAuthenticated, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  // Extract username from req.user
  const { username } = req.user;

  try {
    // Find the user by username in the database
    const user = await User.findOne({ username });

    if (user) {
      // Compare the provided current password with the stored bcrypt hash
      const isMatch = await bcrypt.compare(currentPassword, user.password);

      if (isMatch) {
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the user document
        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password changed successfully' });
      } else {
        res.status(401).json({ message: 'Invalid current password' });
      }
    } else {
      res.status(401).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error during password change:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/adddata', isAuthenticated, async (req, res) => {
  const data = req.body;
 

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const existingData = await collection.findOne({ Zetacode: data.Zetacode });

    if (existingData) {
      client.close();
      return res.status(400).json({ message: 'Zetacode must be unique' });
    }

    // Add the username field to the data object
    data.username = "name";

    // Insert the new document into the collection
    await collection.insertOne(data);

    client.close();

    res.json({ message: 'Data added successfully' });
  } catch (error) {
    console.error('Error while adding data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/getdata', isAuthenticated, async (req, res) => {
  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const query = buildQuery(req.query);

    console.log('Query:', query);

    const data = await collection.find(query, { projection: { _id: 0, additionalData: 0 } }).toArray();

    client.close();

    res.json(data);
  } catch (error) {
    console.error('Error while retrieving data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/generateCSV', isAuthenticated, async (req, res) => {
  try {
    // Connect to the MongoDB database
    const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority', { useUnifiedTopology: true });
    await client.connect();
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');
    const query = buildQuery(req.query);

    // Fetch the collection documents
    const data = await collection.find(query,{}).toArray();

    // Collect unique headers from all rows
    const uniqueHeadersSet = new Set();
    data.forEach(row => {
      Object.keys(row).forEach(key => uniqueHeadersSet.add(key));
    });

    const uniqueHeaders = Array.from(uniqueHeadersSet);

    // Set response headers for file download
    res.setHeader('Content-Disposition', 'attachment; filename=output.csv');
    res.setHeader('Content-Type', 'text/csv');

    // Create a writable stream to store CSV data in memory
    const csvStream = fastcsv.format({ headers: true });

    // Pipe the CSV data to the response with the unique headers
    csvStream.pipe(res);
    csvStream.write(uniqueHeaders); // Write the header row

    // Write the data rows to the CSV stream
    data.forEach(item => {
      const rowData = uniqueHeaders.map(header => item[header]);
      csvStream.write(rowData);
    });

    // End the stream to finish the response
    csvStream.end();

    // Close the MongoDB connection
    await client.close();
  } catch (error) {
    console.error('Error while generating CSV file:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.get('/generateExcel', isAuthenticated, async (req, res) => {
  try {
    // Connect to the MongoDB database
    const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority', { useUnifiedTopology: true });
    await client.connect();
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');
    const query = buildQuery(req.query);

    // Fetch the collection documents
    const data = await collection.find(query,{}).toArray();

    // Close the MongoDB connection
    await client.close();

    // Check if any data was found
    if (data.length === 0) {
      return res.status(404).json({ message: 'No data found' });
    }

    // Create a new Excel workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Data');

    // Collect unique headers from all rows
    const uniqueHeadersSet = new Set();
    data.forEach(row => {
      Object.keys(row).forEach(key => uniqueHeadersSet.add(key));
    });

    const uniqueHeaders = Array.from(uniqueHeadersSet);

    // Add unique headers to the worksheet
    worksheet.addRow(uniqueHeaders);

    // Add data rows to the worksheet
    data.forEach(row => {
      const rowData = uniqueHeaders.map(header => row[header]);
      worksheet.addRow(rowData);
    });

    // Generate a unique filename for the Excel file
    const excelBuffer = await workbook.xlsx.writeBuffer();

    // Set response headers for file download
    res.setHeader('Content-Disposition', 'attachment; filename=output.xlsx');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

    // Send the in-memory Excel data to the client
    res.send(excelBuffer);
  } catch (error) {
    console.error('Error while generating Excel file:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

function buildQuery(queryParams) {
  const query = {};

  function addRangeQuery(field, minKey, maxKey) {
    const min = parseFloat(queryParams[minKey]);
    const max = parseFloat(queryParams[maxKey]);

    if (!isNaN(min) && !isNaN(max)) {
      query[field] = { $gte: min, $lte: max };
    }
  }

  addRangeQuery('HotTemperature', 'minHotTemperature', 'maxHotTemperature');
  addRangeQuery('HotFlow', 'minHotflow', 'maxHotflow');
  addRangeQuery('ColdFlow', 'minColdFlow', 'maxColdFlow');
  addRangeQuery('ColdReturn', 'minColdReturn', 'maxColdReturn');
  addRangeQuery('HotFlushTemperature', 'minHotFlushTemperature', 'maxHotFlushTemperature');
  addRangeQuery('HotReturn', 'minHotReturn', 'maxHotReturn');
  addRangeQuery('ColdTemperature', 'minColdTemperature', 'maxColdTemperature');

  const startDate = new Date(queryParams.startDate);
  const endDate = new Date(queryParams.endDate);

  if (!isNaN(startDate.getTime()) && !isNaN(endDate.getTime())) {
    const formattedStartDate = startDate.toISOString().split('T')[0];
    const formattedEndDate = endDate.toISOString().split('T')[0];

    query.Date = { $gte: formattedStartDate, $lte: formattedEndDate };

    console.log('Formatted Start Date:', formattedStartDate);
    console.log('Formatted End Date:', formattedEndDate);
  } else {
    console.error('Invalid startDate or endDate');
    // Handle the error, e.g., return an error response
  }

  const zetacode = parseInt(queryParams.zetacode);
  if (!isNaN(zetacode)) {
    query.Zetacode = zetacode;
  }

  return query;
}

app.get('/getsingledata/:id', isAuthenticated, async (req, res) => {
  const zetacode = parseInt(req.params.id, 10); // Parse the 'id' parameter as an integer

  if (isNaN(zetacode)) {
    return res.status(400).json({ message: 'Zetacode must be a valid number' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const data = await collection.findOne({ Zetacode: zetacode }, { projection: { _id: 0 } });

    console.log(data);

    client.close();

    if (data) {
      return res.json({ data: data });
    } else {
      return res.status(404).json({ message: 'Data not found' });
    }
  } catch (error) {
    console.error('Error while retrieving data:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});



app.post('/getdatabydate', isAuthenticated, async (req, res) => {
  const { date } = req.body;

  if (!date) {
    return res.status(400).json({ message: 'Date not provided' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const data = await collection.find({ Date: date }).toArray();

    client.close();

    res.json(data);
    } catch (error) {
    console.error('Error while retrieving data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/deletedata', isAuthenticated, async (req, res) => {
 
  const { zetacode } = req.body;
 
  try { 
   
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const result = await collection.deleteOne({ Zetacode: zetacode });
    console.log(result);


    client.close();

    if (result.deletedCount === 1) {
      res.json({ message: 'Data deleted successfully' });
    } else {
      res.status(404).json({ message: 'Data not found' });
    }
  } catch (error) {
    console.error('Error while deleting data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/deletedatabydate', isAuthenticated, async (req, res) => {
  const { date } = req.body;

  if (!date) {
    return res.status(400).json({ message: 'Date not provided in the request body' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    const result = await collection.deleteMany({ Date: date });

    client.close();

    if (result.deletedCount > 0) {
      res.json({ message: `${result.deletedCount} data(s) deleted successfully` });
    } else {
      res.status(404).json({ message: 'No data found' });
    }
  } catch (error) {
    console.error('Error while deleting data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/updatedata', isAuthenticated, async (req, res) => {
  
  const { zetacode, newData } = req.body;

  if (!zetacode || !newData) {
    return res.status(400).json({ message: 'Zetacode or new data not provided in the request body' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');
    if (newData._id) {
      delete newData._id;
    }

    const result = await collection.updateOne({ Zetacode: zetacode }, { $set: newData });

    client.close();

    if (result.matchedCount === 1) {
      res.json({ message: 'Data updated successfully' });
    } else if (result.matchedCount === 0) {
      res.status(404).json({ message: 'Data not found' });
    } else {
      res.status(500).json({ message: 'Multiple data matched. Update failed.' });
    }
  } catch (error) {
    console.error('Error while updating data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.put('/updatedataTable', async (req, res) => {
  const newFielddata  = req.body.newFielddata;

  try {
    // Check if newFielddata is null or undefined
    if (!newFielddata) {
      return res.status(400).json({ message: 'Invalid request. newFielddata is null or undefined.' });
    }

    // Check if newFielddata contains any fields
    if (Object.keys(newFielddata).length === 0) {
      return res.status(400).json({ message: 'Invalid request. newFielddata must contain fields to update.' });
    }

    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    // Specify the query to match all documents (empty query)
    const query = {};

    // Specify the update operation to add a new field
    const updateOperation = { $set: newFielddata };

    // Update all documents in the collection
    const result = await collection.updateMany(query, updateOperation);

    client.close();

    if (result) {
      res.json({ message: 'Data updated successfully' });
    }
  } catch (error) {
    console.error('Error while updating data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/deleteColumn/:columnName', async (req, res) => {
  const columnName = req.params.columnName;

  try {
    // Check if columnName is null or undefined
    if (!columnName) {
      return res.status(400).json({ message: 'Invalid request. columnName is null or undefined.' });
    }

    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority');
    const db = client.db('Mydatabase');
    const collection = db.collection('maindatas');

    // Specify the update operation to remove a field
    const updateOperation = { $unset: { [columnName]: 1 } };

    // Update all documents in the collection
    const result = await collection.updateMany({}, updateOperation);

    client.close();

    if (result.modifiedCount > 0) {
      res.json({ message: `Column '${columnName}' deleted successfully` });
    } else {
      res.status(404).json({ message: `Column '${columnName}' not found` });
    }
  } catch (error) {
    console.error('Error while deleting column:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/importcsv', isAuthenticated, upload.single('file'), async (req, res) => {
  let client;
  let successCount = 0;
  let errorCount = 0;
  let responseDetails = {
    success: [],
    errors: [],
  };

  try {
    console.log('Entered route');

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ message: 'No file uploaded or file buffer is empty' });
    }

    const fileBuffer = req.file.buffer;

    console.log('File Buffer Content:', fileBuffer.toString());

    const readableStream = stream.Readable.from(fileBuffer.toString());

    await new Promise(async (resolve, reject) => {
      let processedCount = 0;
      let totalRecords = 0;

      readableStream
        .pipe(csv())
        .on('data', async (data) => {
          try {
            console.log('Processing data:', data);

            const username = "sd";

            const rowWithUsername = {
              Location: data.Location,
              Zetacode: parseInt(data.Zetacode),
              Room: data.Room,
              HelpDeskReference: data.HelpDeskReference,
              IPS: data.IPS === 'true',
              Fault: data.Fault,
              Date: new Date(data.Date),
              HotTemperature: parseFloat(data.HotTemperature),
              HotFlow: parseFloat(data.HotFlow),
              HotReturn: parseFloat(data.HotReturn),
              ColdTemperature: parseFloat(data.ColdTemperature),
              ColdFlow: parseFloat(data.ColdFlow),
              ColdReturn: parseFloat(data.ColdReturn),
              HotFlushTemperature: parseFloat(data.HotFlushTemperature),
              TapNotSet: data.TapNotSet === 'true',
              ColdFlushTemperature: parseFloat(data.ColdFlushTemperature),
              TMVFail: data.TMVFail === 'true',
              PreflushSampleTaken: data.PreflushSampleTaken === 'true',
              PostflushSampleTaken: data.PostflushSampleTaken === 'true',
              ThermalFlush: data.ThermalFlush,
            };

            client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/Mydatabase?retryWrites=true&w=majority', { useUnifiedTopology: true });

            await client.connect();

            const db = client.db('Mydatabase');
            const collection = db.collection('maindatas');

            await collection.insertOne(rowWithUsername);

            console.log('Data inserted successfully');

            successCount++;
            responseDetails.success.push({ _id: data.HelpDeskReference, message: 'Record inserted successfully' });
          } catch (error) {
            if (error instanceof MongoError && error.code === 11000) {
              console.error('Duplicate key error:', error);
              responseDetails.errors.push({ _id: data.HelpDeskReference, message: 'Duplicate key error: Some records already exist in the database.', error });
              errorCount++;
            } else {
              console.error('Error inserting data:', error);
              responseDetails.errors.push({ _id: data.HelpDeskReference, message: 'Internal server error: Failed to insert the record into the database.', error });
              errorCount++;
              reject(error);
            }
          } finally {
            processedCount++;

            // Check if all records have been processed
            if (processedCount === totalRecords) {
              resolve();
            }
          }
        })
        .on('end', () => {
          // Response will be sent in the 'resolve' block
        })
        .on('error', (error) => {
          console.error('CSV processing error:', error);
          responseDetails.errors.push({ _id: null, message: 'Error processing CSV', error });
          res.status(400).json({ message: 'Error processing CSV', error });
          reject(error);
        })
        .on('data', () => {
          totalRecords++;
        })
        .on('end', () => {
          if (totalRecords === 0) {
            res.status(400).json({ message: 'No records found in the CSV file' });
            reject('No records found in the CSV file');
          }
        });
    });

    // Include success and error counts in the response message
    res.json({
      message: 'CSV data imported successfully',
      successCount,
      errorCount,
      details: responseDetails,
    });

    console.log('Route execution completed');
  } catch (error) {
    console.error('Error while importing CSV:', error);
    res.status(500).json({ message: 'Internal server error' });
  } finally {
    if (client) {
      await client.close();
    }
  }
});





app.post('/createUser', isAuthenticated, async (req, res) => {
  const { username, password, permission } = req.body;

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user with hashed password and initialized session object
    const newUser = new User({
      username,
      password: hashedPassword,
      permission,
      session: {
        sessionId: '',
        expiresAt: null,
        createdAt: null,
        ipAddress: '',
        userAgent: '',
      },
    });

    // Save the user to the database
    await newUser.save();

    res.json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error while creating user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/deleteUser', isAuthenticated, isAdmin, async (req, res) => {
  const { usernameToDelete } = req.body;

  try {
       // Check if the user to delete exists
    const userToDelete = await User.findOne({ username: usernameToDelete });
    if (!userToDelete) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Perform the delete operation
    await User.deleteOne({ username: usernameToDelete });

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error while deleting user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/editUserPermission', isAuthenticated, isAdmin, async (req, res) => {
  const { usernameToEdit, permission } = req.body;

  try {
    // Check if the user to edit exists
    const userToEdit = await User.findOne({ username: usernameToEdit });
    if (!userToEdit) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update the user's permissions
    userToEdit.permission = permission;
    await userToEdit.save();

    res.json({ message: 'User permissions updated successfully' });
  } catch (error) {
    console.error('Error while editing user permissions:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/fetchUsers', isAuthenticated, async (req, res) => {
  const loggedInUsername = req.user.username;

  try {
     // Fetch all documents except the one with the same username as the logged-in user
    const users = await User.find({ username: { $ne: loggedInUsername } }, { username: 1, permission: 1 });

    res.json({ users });
  } catch (error) {
    console.error('Error while fetching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


