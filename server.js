const express = require('express');
const dbConn = require('./db/db.js');
const session = require('express-session');
const { MongoClient } = require('mongodb');
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

mongoose.set('strictQuery', false);

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
// app.use(
//   session({
//     secret: secretKey,
//     resave: false,
//     saveUninitialized: false,
//   })
// );

// Middleware to check authentication
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
    const decoded = jwt.verify(token, 'your-secret-key');

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

  try {
    // Find the user by username in the database
    const user = await User.findOne({ username });

    if (user) {
      // Compare the provided password with the stored bcrypt hash
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        // Generate a JWT token with the user's information
        const token = jwt.sign(
          {
            username: user.username,
            permission: user.permission,
          },
          'your-secret-key', // Replace with a secure secret key
          { expiresIn: '1h' } // Token expiration time
        );

        res.json({
          token,
          expiresIn: '1h', // Example expiration time, you can customize this
          tokenType: 'Bearer', // Specify the token type (e.g., Bearer)
          authUserState: 'authenticated', // Example authentication state
          refreshToken: 'your-refresh-token', // Replace with the actual refresh token
          refreshTokenExpireIn: '7d', // Example refresh token expiration time
        });
      }}}
 catch (error) {
    console.error('Error during sign-in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
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
app.post('/auth/changepassword', isAuthenticated, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const username = req.session.username;

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
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
    const collection = db.collection('maindatas');

    const data = await collection.find().toArray();

    client.close();

    res.json(data);
  } catch (error) {
    console.error('Error while retrieving data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/getsingledata/:id', isAuthenticated, async (req, res) => {
  const loggedInUserPermission = req.session.permission;
  const zetacode  = req.params.id;

  if (!zetacode) {
    return res.status(400).json({ message: 'Zetacode not provided in the request body' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
    const collection = db.collection('maindatas');
    const zeta = Number(zetacode)
    const data = await collection.findOne({ Zetacode: zeta });
console.log(data);
    client.close();

    if (data) {
     return res.json(data);
    } else {
     return  res.status(404).json({ message: 'Data not found' });
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
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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
   
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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

app.put('/updatedata', isAuthenticated, canEdit, async (req, res) => {
  
  const { zetacode, newData } = req.body;

  if (!zetacode || !newData) {
    return res.status(400).json({ message: 'Zetacode or new data not provided in the request body' });
  }

  try {
    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
    const collection = db.collection('maindatas');

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

    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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

    const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority');
    const db = client.db('database');
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
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const buffer = req.file.buffer;
    const data = buffer.toString('utf8');

    const rows = [];

    // Use the csv-parser library to parse the CSV data
    csv({ headers: true })
      .on('data', (data) => rows.push(data))
      .on('end', async () => {
        const client = await MongoClient.connect('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&m=majority');
        const db = client.db('database');
        const collection = db.collection('sessions');

        for (const row of rows) {
          try {
            // Add the username column to each row
            const rowWithUsername = {
              ...row,
              username: "username",
            };

            await collection.insertOne(rowWithUsername);
          } catch (error) {
            console.error('Error while inserting data:', error);
          }
        }

        client.close();

        res.json({ message: 'CSV data imported successfully' });
      });

    // Pipe the CSV data into the csv-parser stream
    streamifier.createReadStream(data).pipe(csv());
  } catch (error) {
    console.error('Error while importing CSV:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/createUser', isAuthenticated, isAdmin, async (req, res) => {
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


app.get('/fetchUsers', isAuthenticated, isAdmin, async (req, res) => {
  const loggedInUsername = req.session.username;

  try {
     // Fetch all documents except the one with the same username as the logged-in user
    const users = await User.find({ username: { $ne: loggedInUsername } }, { username: 1, permission: 1 });

    res.json({ users });
  } catch (error) {
    console.error('Error while fetching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/generateCSV', isAuthenticated, async (req, res) => {
  try {
    // Connect to the MongoDB database
    const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority', { useUnifiedTopology: true });
    await client.connect();
    const db = client.db('database');
    const collection = db.collection('maindatas');

    // Fetch the collection documents
    const data = await collection.find({}).toArray();

    // Set response headers for file download
    res.setHeader('Content-Disposition', 'attachment; filename=output.csv');
    res.setHeader('Content-Type', 'text/csv');

    // Create a writable stream to store CSV data in memory
    const csvStream = fastcsv.format({ headers: true });

    // Pipe the CSV data to the response
    csvStream.pipe(res);

    // Write the data to the CSV stream
    data.forEach(item => csvStream.write(item));

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
    const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority', { useUnifiedTopology: true });
    await client.connect();
    const db = client.db('database');
    const collection = db.collection('maindatas');

    // Fetch the collection documents
    const data = await collection.find().toArray();

    // Close the MongoDB connection
    await client.close();

    // Check if any data was found
    if (data.length === 0) {
      return res.status(404).json({ message: 'No data found' });
    }

    // Create a new Excel workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Data');

    // Add headers to the worksheet
    const headers = Object.keys(data[0]);
    worksheet.addRow(headers);

    // Add data rows to the worksheet
    data.forEach(row => worksheet.addRow(Object.values(row)));

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


// app.get('/generateExcel', isAuthenticated, async (req, res) => {
//   try {

//     // Connect to the MongoDB database
//     const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority', { useUnifiedTopology: true });
//     await client.connect();
//     const db = client.db('database');
//     const collection = db.collection('maindatas');

//     // Construct the query based on the provided date parameter

//     // Fetch the collection documents based on the query
//     const data = await collection.find().toArray();

//     // Close the MongoDB connection
//     await client.close();

//     // Check if any data was found
//     if (data.length === 0) {
//       return res.status(404).json({ message: 'No data found for the provided date' });
//     }

//     // Create a new Excel workbook and worksheet
//     const workbook = new ExcelJS.Workbook();
//     const worksheet = workbook.addWorksheet('Data');

//     // Add headers to the worksheet
//     const headers = Object.keys(data[0]);
//     worksheet.addRow(headers);

//     // Add data rows to the worksheet
//     data.forEach(row => {
//       const values = Object.values(row);
//       worksheet.addRow(values);
//     });

//     // Generate a unique filename for the Excel file
//     const excelFilePath = `output_${Date.now()}.xlsx`;

//     // Save the workbook to the Excel file
//     await workbook.xlsx.writeFile(excelFilePath);

//     // Set response headers for file download
//     res.setHeader('Content-Disposition', `attachment; filename=${excelFilePath}`);
//     res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

//     // Stream the file to the response
//     res.sendFile(excelFilePath, { root: __dirname }, () => {
//       // Remove the file after it has been sent
//       fs.unlink(excelFilePath, err => {
//         if (err) {
//           console.error('Error while deleting the Excel file:', err);
//         } else {
//           console.log('Excel file deleted successfully.');
//         }
//       });
//     });
//   } catch (error) {
//     console.error('Error while generating Excel file:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// app.get('/generateCSV', async (req, res) => {
//   try {
//     const { date } = req.query; // Retrieve the query parameter "date"

//     // Connect to the MongoDB database
//     const client = new MongoClient('mongodb+srv://andifab23:9801TJmE0HGLgQkO@senay.9gryt4n.mongodb.net/?retryWrites=true&w=majority', { useUnifiedTopology: true });
//     await client.connect();
//     const db = client.db('database');
//     const collection = db.collection('maindatas');

//     // Construct the query based on the provided date parameter
//     const query = date ? { date: { $eq: date } } : {}; // Adjust the field name "date" accordingly

//     // Fetch the collection documents based on the query
//     const data = await collection.find(query).toArray();

//     // Close the MongoDB connection
//     await client.close();

//     // Check if any data was found
//     if (data.length === 0) {
//       return res.status(404).json({ message: 'No data found for the provided date' });
//     }

//     // Define the CSV writer and specify the file path
//     const csvFilePath = 'output.csv';
//     const csvWriter = createCsvWriter({
//       path: csvFilePath,
//       header: Object.keys(data[0]).map(key => ({ id: key, title: key }))
//     });

//     // Write the data to the CSV file
//     await csvWriter.writeRecords(data);

//     // Set response headers for file download
//     res.setHeader('Content-Disposition', 'attachment; filename=output.csv');
//     res.setHeader('Content-Type', 'text/csv');

//     // Stream the file to the response
//     res.download(csvFilePath, () => {
//       // Remove the file after it has been sent
//       fs.unlink(csvFilePath, err => {
//         if (err) {
//           console.error('Error while deleting the CSV file:', err);
//         } else {
//           console.log('CSV file deleted successfully.');
//         }
//       });
//     });
//   } catch (error) {
//     console.error('Error while generating CSV file:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });