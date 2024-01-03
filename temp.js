const bcrypt = require('bcrypt');

// Assuming 'password' is the admin's provided password
const password = 'admin123';

// Generate a bcrypt hash of the password
const hashedPassword = bcrypt.hashSync(password, 10);

console.log(hashedPassword);


app.post('/adddata', async (req, res) => {
    const data = req.body;
  
    try {
      const existingData = await MainData.findOne({ Zetacode: data.Zetacode });
  
      if (existingData) {
        return res.status(400).json({ message: 'Zetacode must be unique' });
      }
      // Create a new document using the MainData model
      const newData = new MainData(data);
  
      // Save the new document to the database
      await newData.save();
  
      res.json({ message: 'Data added successfully' });
    } catch (error) {
      console.error('Error while adding data:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });