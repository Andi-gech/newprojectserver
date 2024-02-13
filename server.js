const express = require("express");
const dbManager = require("./db.js");
const { MongoError, ObjectId } = require("mongodb");

const bcrypt = require("bcrypt");
const app = express();

const multer = require("multer");
const moment = require("moment");
const csv = require("csv-parser");
const ExcelJS = require("exceljs");
const cors = require("cors");
const fastcsv = require("fast-csv");
const jwt = require("jsonwebtoken");
const stream = require("stream");
const winston = require("winston");
let mainDataCollection;
let userDataCollection;
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

async function startServer() {
  try {
    const db = await dbManager.connectToDatabase();
    mainDataCollection = db.collection("maindatas");
    userDataCollection = db.collection("users");

    app.listen(9050, () => {
      console.log("Server running on port 9050");
    });
  } catch (error) {
    console.error("Failed to establish database connection:", error);
    logger.error("An error occurred in Db connection:", error);
  }
}

// const secretKey = crypto.randomBytes(64).toString("hex");
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const currentTime = new Date();
// const expirationTime = new Date(currentTime.getTime() + 60 * 60 * 1000);

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const isAuthenticated = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const [tokenType, token] = authHeader.split(" ");

  if (!tokenType || tokenType.toLowerCase() !== "jwt" || !token) {
    return res.status(401).json({ message: "Invalid token type or format" });
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, "1q2w3e4r5t");

    // Attach user information to the request object
    req.user = decoded;

    next();
  } catch (error) {
    console.error("Error during authentication:", error);
    logger.error("Error during authentication:", error);
    res.status(401).json({ message: "Invalid token" });
  }
};

// Middleware to check role
const canEdit = (req, res, next) => {
  const loggedInUserPermission = req.user.permission;
  if (
    loggedInUserPermission !== "admin" &&
    loggedInUserPermission !== "editor"
  ) {
    return res
      .status(403)
      .json({ message: "Only admins and editors have this privilege" });
  } else {
    next();
  }
};

// Middleware to verify admin role
const isAdmin = (req, res, next) => {
  const loggedInUserPermission = req.user.permission;
  // Check if the logged-in user has admin permissions
  if (loggedInUserPermission !== "admin") {
    return res.status(403).json({ message: "Only admins has this privilege" });
  } else {
    next();
  }
};

// Sign-in route
app.post("/auth/signin", async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password);

  try {
    // Find the user by username in the database
    const user = await userDataCollection.findOne({ username });

    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        const accessToken = jwt.sign(
          {
            username: user.username,
            permission: user.permission,
          },
          "1q2w3e4r5t",
          { expiresIn: 86400 }
        );

        // Generate a refresh token
        const refreshToken = jwt.sign(
          { username: user.username },
          "your-refresh-secret-key",
          { expiresIn: 432000 }
        );

        res.json({
          accessToken,
          expiresIn: 86400,
          tokenType: "Jwt",
          authUserState: "authenticated",
          username: user.username,
          permission: user.permission,
          refreshToken,
          refreshTokenExpireIn: 432000,
        });
      } else {
        res.status(401).json({ message: "Invalid password" });
      }
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    logger.error("An error occurred During Sign-in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.post("/auth/refresh", async (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is missing" });
  }

  jwt.verify(refreshToken, "your-refresh-secret-key", async (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Check if the user exists in the database
    const user = await userDataCollection.findOne({
      username: decoded.username,
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a new access token
    const newAccessToken = jwt.sign(
      {
        username: user.username,
        permission: user.permission,
      },
      "1q2w3e4r5t",
      { expiresIn: 86400 }
    );

    res.json({
      accessToken: newAccessToken,
      expiresIn: 86400,
      tokenType: "Jwt",
      authUserState: "authenticated",
    });
  });
});

app.post("/auth/changepassword", isAuthenticated, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // Extract username from req.user
  const { username } = req.user;

  try {
    // Find the user by username in the database
    const user = await userDataCollection.findOne({ username });

    if (user) {
      // Compare the provided current password with the stored bcrypt hash
      const isMatch = await bcrypt.compare(currentPassword, user.password);

      if (isMatch) {
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the user document
        await userDataCollection.updateOne(
          { username },
          { $set: { password: hashedPassword } }
        );

        res.json({ message: "Password changed successfully" });
      } else {
        res.status(401).json({ message: "Invalid current password" });
      }
    } else {
      res.status(401).json({ message: "User not found" });
    }
  } catch (error) {
    console.error("Error during password change:", error);
    logger.error("An error occurred during password change:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/adddata", [isAuthenticated, canEdit], async (req, res) => {
  const data = req.body;

  try {
    await mainDataCollection.insertOne(data);

    res.json({ message: "Data added successfully" });
  } catch (error) {
    console.error("Error while adding data:", error);
    logger.error("An error occurred while adding data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/getdata", isAuthenticated, async (req, res) => {
  try {
    const pageSize = 10;
    const page = parseInt(req.query.page) || 1; 

    const skip = (page - 1) * pageSize;

    const query = buildQuery(req.query);

    console.log("Query:", query);

    const totalDocs = await mainDataCollection.countDocuments(query);

    const totalPages = Math.ceil(totalDocs / pageSize);

    const data = await mainDataCollection
      .find(query, { projection: { additionalData: 0 } })
      .skip(skip)
      .limit(pageSize)
      .toArray();

    const formattedData = data.map((item) => {
      return {
        Location: item.Location,
        Zetacode: item.Zetacode,
        ...item,
        IPS: item.IPS ? "yes" : item.IPS === false ? "no" : "",
        TapNotSet: item.TapNotSet
          ? "yes"
          : item.TapNotSet === false
          ? "no"
          : "",
        TMVFail: item.TMVFail ? "yes" : item.TMVFail === false ? "no" : "",
        PreflushSampleTaken: item.PreflushSampleTaken
          ? "yes"
          : item.PreflushSampleTaken === false
          ? "no"
          : "",
        PostflushSampleTaken: item.PostflushSampleTaken
          ? "yes"
          : item.PostflushSampleTaken === false
          ? "no"
          : "",
        Date: item.Date ? moment(item.Date).format("YYYY-MM-DD") : null,
      };
    });

    // Build pagination links
    let next = null;
    let previous = null;
    if (page < totalPages) {
      next = `/getdata?page=${page + 1}${getQueryString(req.query)}`;
    }
    if (page > 1) {
      previous = `/getdata?page=${page - 1}${getQueryString(req.query)}`;
    }
    // Return data along with pagination links
    res.json({
      count: totalDocs,
      next,
      previous,
      results: formattedData,
    });
  } catch (error) {
    console.error("Error while retrieving data:", error);
    logger.error("An error occurred while retrieving data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

function getQueryString(query) {
  let queryString = "";
  for (const key in query) {
    if (query.hasOwnProperty(key) && key !== "page") {
      queryString += `&${key}=${query[key]}`;
    }
  }
  return queryString;
}
app.get("/generateCSV", isAuthenticated, async (req, res) => {
  try {
    const query = buildQuery(req.query);

    const data = await mainDataCollection
      .find(query, { projection: { _id: 0 } })
      .toArray();
    const formattedData = data.map((item) => {
      return {
        ...item,
        Date: item.Date ? moment(item.Date).format("YYYY-MM-DD") : null,
      };
    });

    // Collect unique headers from all rows
    const uniqueHeadersSet = new Set();
    formattedData.forEach((row) => {
      Object.keys(row).forEach((key) => uniqueHeadersSet.add(key));
    });

    const uniqueHeaders = Array.from(uniqueHeadersSet);

    // Set response headers for file download
    res.setHeader("Content-Disposition", "attachment; filename=output.csv");
    res.setHeader("Content-Type", "text/csv");

    // Create a writable stream to store CSV data in memory
    const csvStream = fastcsv.format({ headers: true });

    // Pipe the CSV data to the response with the unique headers
    csvStream.pipe(res);
    csvStream.write(uniqueHeaders); // Write the header row

    // Write the data rows to the CSV stream
    formattedData.forEach((item) => {
      const rowData = uniqueHeaders.map((header) => item[header]);
      csvStream.write(rowData);
    });

    // End the stream to finish the response
    csvStream.end();
  } catch (error) {
    console.error("Error while generating CSV file:", error);
    logger.error("An error occurred while generating CSV file:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.get("/generateExcel", isAuthenticated, async (req, res) => {
  try {
    const query = buildQuery(req.query);

    const data = await mainDataCollection
      .find(query, { projection: { _id: 0 } })
      .toArray();

    // Check if any data was found
    if (data.length === 0) {
      return res.status(404).json({ message: "No data found" });
    }

    // Create a new Excel workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Data");

    // Collect unique headers from all rows
    const uniqueHeadersSet = new Set();
    data.forEach((row) => {
      Object.keys(row).forEach((key) => uniqueHeadersSet.add(key));
    });

    const uniqueHeaders = Array.from(uniqueHeadersSet);

    // Add unique headers to the worksheet
    worksheet.addRow(uniqueHeaders);

    // Add data rows to the worksheet
    data.forEach((row) => {
      const rowData = uniqueHeaders.map((header) => row[header]);
      worksheet.addRow(rowData);
    });

    const excelBuffer = await workbook.xlsx.writeBuffer();

    // Set response headers for file download
    res.setHeader("Content-Disposition", "attachment; filename=output.xlsx");
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    // Send the in-memory Excel data to the client
    res.send(excelBuffer);
  } catch (error) {
    console.error("Error while generating Excel file:", error);
    logger.error("An error occurred while generating Excel file:", error);
    res.status(500).json({ message: "Internal server error" });
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

  addRangeQuery("HotTemperature", "minHotTemperature", "maxHotTemperature");
  addRangeQuery("HotFlow", "minHotflow", "maxHotflow");
  addRangeQuery("ColdFlow", "minColdFlow", "maxColdFlow");
  addRangeQuery("ColdReturn", "minColdReturn", "maxColdReturn");
  addRangeQuery(
    "HotFlushTemperature",
    "minHotFlushTemperature",
    "maxHotFlushTemperature"
  );
  addRangeQuery("HotReturn", "minHotReturn", "maxHotReturn");
  addRangeQuery("ColdTemperature", "minColdTemperature", "maxColdTemperature");

  console.log(queryParams.startDate);
  console.log(queryParams.endDate);

  const startDate = moment(queryParams.startDate, "YYYY-MM-DD").toDate();
  const endDate = moment(queryParams.endDate, "YYYY-MM-DD").toDate();

  console.log(startDate);
  console.log(endDate);
  if (!isNaN(startDate) && !isNaN(endDate)) {
    query.Date = { $gte: startDate, $lte: endDate };
  } else {
    console.error("Invalid startDate or endDate");
  }

  const zetacode = parseInt(queryParams.zetacode);
  if (!isNaN(zetacode)) {
    query.Zetacode = zetacode;
  }
  if (queryParams.floorNumber) {
    query.Floor = parseInt(queryParams.floorNumber, 10);
  } else if (queryParams.emptyFloor) {
    query.Floor = { $in: [null, undefined] };
  }

  return query;
}

app.get("/getsingledata/:id", isAuthenticated, async (req, res) => {
  const documentId = req.params.id;

  if (!ObjectId.isValid(documentId)) {
    return res.status(400).json({ message: "Invalid document ID" });
  }

  try {
    const data = await mainDataCollection.findOne(
      { _id: new ObjectId(documentId) },
      { projection: { _id: 0 } }
    );

    if (data) {
      return res.json({ data: data });
    } else {
      return res.status(404).json({ message: "Data not found" });
    }
  } catch (error) {
    console.error("Error while retrieving data:", error);
    logger.error("An error occurred while retrieving data:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/deletedata", [isAuthenticated, canEdit], async (req, res) => {
  const { id } = req.body;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid document ID" });
  }

  try {
    const result = await mainDataCollection.deleteOne({
      _id: new ObjectId(id),
    });
    console.log(result);

    if (result.deletedCount === 1) {
      res.json({ message: "Data deleted successfully" });
    } else {
      res.status(404).json({ message: "Data not found" });
    }
  } catch (error) {
    console.error("Error while deleting data:", error);
    logger.error("An error occurred while deleting data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/updatedata", [isAuthenticated, canEdit], async (req, res) => {
  const { id, newData } = req.body;

  if (!id || !newData) {
    return res
      .status(400)
      .json({ message: "ID or new data not provided in the request body" });
  }

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid document ID" });
  }

  try {
    const query = { _id: new ObjectId(id) };

    if (newData._id) {
      delete newData._id;
    }

    const result = await mainDataCollection.updateOne(query, { $set: newData });

    if (result.matchedCount === 1) {
      res.json({ message: "Data updated successfully" });
    } else if (result.matchedCount === 0) {
      res.status(404).json({ message: "Data not found" });
    } else {
      res
        .status(500)
        .json({ message: "Multiple data matched. Update failed." });
    }
  } catch (error) {
    console.error("Error while updating data:", error);
    logger.error("An error occurred while updating data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/updatedataTable", [isAuthenticated, canEdit], async (req, res) => {
  const newFielddata = req.body.newFielddata;

  try {
    if (!newFielddata) {
      return res.status(400).json({
        message: "Invalid request. newFielddata is null or undefined.",
      });
    }

    // Check if newFielddata contains any fields
    if (Object.keys(newFielddata).length === 0) {
      return res.status(400).json({
        message: "Invalid request. newFielddata must contain fields to update.",
      });
    }

    // Specify the query to match all documents (empty query)
    const query = {};

    // Specify the update operation to add a new field
    const updateOperation = { $set: newFielddata };

    // Update all documents in the collection
    const result = await mainDataCollection.updateMany(query, updateOperation);

    if (result) {
      res.json({ message: "Data updated successfully" });
    }
  } catch (error) {
    console.error("Error while updating data:", error);
    logger.error("An error occurred while updating data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete(
  "/deleteColumn/:columnName",
  [isAuthenticated, canEdit],
  async (req, res) => {
    const columnName = req.params.columnName;

    try {
      // Check if columnName is null or undefined
      if (!columnName) {
        return res.status(400).json({
          message: "Invalid request. columnName is null or undefined.",
        });
      }

      // Specify the update operation to remove a field
      const updateOperation = { $unset: { [columnName]: 1 } };

      // Update all documents in the collection
      const result = await mainDataCollection.updateMany({}, updateOperation);

      if (result.modifiedCount > 0) {
        res.json({ message: `Column '${columnName}' deleted successfully` });
      } else {
        res.status(404).json({ message: `Column '${columnName}' not found` });
      }
    } catch (error) {
      console.error("Error while deleting column:", error);
      logger.error("An error occurred while deleting column:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

app.post(
  "/importcsv",
  [isAuthenticated, canEdit],
  upload.single("file"),
  async (req, res) => {
    let successCount = 0;
    let errorCount = 0;
    let responseDetails = {
      success: [],
      errors: [],
    };
    let processedCount = 0;
    let totalRecords = 0;

    try {
      console.log("Entered route");

      if (!req.file || !req.file.buffer) {
        return res
          .status(400)
          .json({ message: "No file uploaded or file buffer is empty" });
      }

      const fileBuffer = req.file.buffer;

      console.log("File Buffer Content:", fileBuffer.toString());

      const readableStream = stream.Readable.from(fileBuffer.toString());

      const bulkOps = [];

      await new Promise(async (resolve, reject) => {
        readableStream
          .pipe(csv())
          .on("data", async (data) => {
            try {
              const cleanedData = {};
              for (const key in data) {
                if (data.hasOwnProperty(key)) {
                  const cleanedKey = key.replace(/\s+/g, "");
                  cleanedData[cleanedKey] = data[key];
                }
              }

              console.log(cleanedData);

              let formattedDate;
              if (data.Date) {
                formattedDate = moment(data.Date, "M/D/YYYY").toDate();
              } else {
                formattedDate = null;
              }
              const validValues = ["yes", "y", "true", "set"];
              const invalidValues = ["no", "n", "false", "notset"];

              const rowWithUsername = {
                ...cleanedData,
                Location: cleanedData.Location,
                Zetacode: parseInt(cleanedData.Zetacode),
                Room: cleanedData.Room,
                Floor: parseInt(cleanedData.Floor),
                HelpDeskReference: cleanedData.HelpDeskReference,
                IPS: validValues.includes(
                  cleanedData?.IPS?.trim()?.toLowerCase()
                )
                  ? true
                  : invalidValues.includes(
                      cleanedData?.IPS?.trim()?.toLowerCase()
                    )
                  ? false
                  : "",
                Fault: cleanedData.Fault,
                Date: formattedDate,
                HotTemperature: parseFloat(cleanedData.HotTemperature),
                HotFlow: parseFloat(cleanedData.HotFlow),
                HotReturn: parseFloat(cleanedData.HotReturn),
                ColdTemperature: parseFloat(cleanedData.ColdTemperature),
                ColdFlow: parseFloat(cleanedData.ColdFlow),
                ColdReturn: parseFloat(cleanedData.ColdReturn),
                HotFlushTemperature: parseFloat(
                  cleanedData.HotFlushTemperature
                ),
                TapNotSet: validValues.includes(
                  cleanedData?.TapNotSet?.trim()?.toLowerCase()
                )
                  ? true
                  : invalidValues.includes(
                      cleanedData?.TapNotSet?.trim()?.toLowerCase()
                    )
                  ? false
                  : "",
                ColdFlushTemperature: parseFloat(
                  cleanedData.ColdFlushTemperature
                ),
                TMVFail: validValues.includes(
                  cleanedData?.TMVFail?.trim()?.toLowerCase()
                )
                  ? true
                  : invalidValues.includes(
                      cleanedData?.TMVFail?.trim()?.toLowerCase()
                    )
                  ? false
                  : "",
                PreflushSampleTaken: validValues.includes(
                  cleanedData?.PreflushSampleTaken?.trim()?.toLowerCase()
                )
                  ? true
                  : invalidValues.includes(
                      cleanedData?.PreflushSampleTaken?.trim()?.toLowerCase()
                    )
                  ? false
                  : "",
                PostflushSampleTaken: validValues.includes(
                  cleanedData?.PostflushSampleTaken?.trim()?.toLowerCase()
                )
                  ? true
                  : invalidValues.includes(
                      cleanedData?.PostflushSampleTaken?.trim()?.toLowerCase()
                    )
                  ? false
                  : "",
                ThermalFlush: cleanedData.ThermalFlush,
              };

              bulkOps.push({ insertOne: { document: rowWithUsername } });

              successCount++;
              responseDetails.success.push({
                _id: data.HelpDeskReference,
                message: "Record inserted successfully",
              });
            } catch (error) {
              if (error instanceof MongoError && error.code === 11000) {
                console.error("Duplicate key error:", error);
                responseDetails.errors.push({
                  _id: data._id,
                  message:
                    "Duplicate key error: Some records already exist in the database.",
                  error,
                });
                errorCount++;
              } else {
                console.error("Error inserting data:", error);
                responseDetails.errors.push({
                  _id: data._id,
                  message:
                    "Internal server error: Failed to insert the record into the database.",
                  error,
                });
                errorCount++;
                reject(error);
              }
            }
          })
          .on("end", () => {
            // After processing all records, perform the bulk insert
            if (bulkOps.length > 0) {
              mainDataCollection
                .bulkWrite(bulkOps)
                .then(() => {
                  resolve();
                })
                .catch((error) => {
                  reject(error);
                });
            } else {
              resolve();
            }
          })
          .on("error", (error) => {
            console.error("CSV processing error:", error);
            responseDetails.errors.push({
              _id: null,
              message: "Error processing CSV",
              error,
            });
            res.status(400).json({ message: "Error processing CSV", error });
            reject(error);
          })
          .on("data", () => {
            // Count the total number of records
            totalRecords++;
          })
          .on("end", () => {
            // If no records found in the CSV file
            if (totalRecords === 0) {
              res
                .status(400)
                .json({ message: "No records found in the CSV file" });
              reject("No records found in the CSV file");
            }
          });
      });

      // Include success and error counts in the response message
      res.json({
        message: "CSV data imported successfully",
        successCount,
        errorCount,
        details: responseDetails,
      });

      console.log("Route execution completed");
    } catch (error) {
      console.error("Error while importing CSV:", error);
      logger.error("An error occurred while importing CSV:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

app.post("/createUser", isAuthenticated, isAdmin, async (req, res) => {
  const { username, password, permission } = req.body;

  try {
    // Check if the username already exists
    const existingUser = await userDataCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user with hashed password and initialized session object
    const newUser = await userDataCollection.insertOne({
      username,
      password: hashedPassword,
      permission,
      session: {
        sessionId: "",
        expiresAt: null,
        createdAt: null,
        ipAddress: "",
        userAgent: "",
      },
    });

    res.json({ message: "User created successfully" });
  } catch (error) {
    console.error("Error while creating user:", error);
    logger.error("An error occurred while creating user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/deleteUser", isAuthenticated, isAdmin, async (req, res) => {
  const { usernameToDelete } = req.body;

  try {
    // Check if the user to delete exists
    const userToDelete = await userDataCollection.findOne({
      username: usernameToDelete,
    });
    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" });
    }

    // Perform the delete operation
    await userDataCollection.deleteOne({ username: usernameToDelete });

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error while deleting user:", error);
    logger.error("An error occurred while deleting user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/editUserPermission", isAuthenticated, isAdmin, async (req, res) => {
  const { usernameToEdit, permission } = req.body;

  try {
    // Check if the user to edit exists
    const userToEdit = await userDataCollection.findOne({
      username: usernameToEdit,
    });
    if (!userToEdit) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update the user's permissions
    userToEdit.permission = permission;
    await userToEdit.save();

    res.json({ message: "User permissions updated successfully" });
  } catch (error) {
    console.error("Error while editing user permissions:", error);
    logger.error("An error occurred while editing user permissions:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/fetchUsers", isAuthenticated, isAdmin, async (req, res) => {
  const loggedInUsername = req.user.username;

  try {
    // Fetch all documents except the one with the same username as the logged-in user
    const users = await userDataCollection
      .find(
        { username: { $ne: loggedInUsername } },
        { projection: { username: 1, permission: 1 } }
      )
      .toArray();

    res.json({ users });
  } catch (error) {
    console.error("Error while fetching users:", error);
    logger.error("An error occurred while fetching users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/getUser/:id", isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    // Check if the provided ID is a valid ObjectId
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    // Find the user by _id in the database
    const user = await userDataCollection.findOne(
      { _id: new ObjectId(userId) },
      { password: 0 }
    );

    if (user) {
      res.json({ user });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error("Error while retrieving user by ID:", error);
    logger.error("An error occurred while retrieving user by ID:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.put(
  "/updateUserPermissions/:id",
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const userId = req.params.id;
    const newPermissions = req.body.permissions;

    try {
      // Check if the provided ID is a valid ObjectId
      if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      // Check if newPermissions is provided
      if (!newPermissions) {
        return res
          .status(400)
          .json({ message: "New permissions are required for the update" });
      }

      // Update user permissions in the database
      const updatedUser = await userDataCollection.findOneAndUpdate(
        { _id: new ObjectId(userId) },
        { $set: { permission: newPermissions } },
        { new: true, projection: { password: 0 } }
      );

      if (updatedUser) {
        res.json({ user: updatedUser });
      } else {
        res.status(404).json({ message: "User not found" });
      }
    } catch (error) {
      console.error("Error while updating user permissions:", error);
      logger.error("An error occurred while updating user permissions:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);
startServer();
