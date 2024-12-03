const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');          // Authentication routes
const whatsappClient = require('./routes/whatsappClient');  // WhatsApp client

// Load environment variables
dotenv.config();

// Initialize the app
const app = express();

// Middleware
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected...'))
  .catch(err => console.log(err));

// Routes
app.use('/api/auth', authRoutes);          // Make sure authRoutes is a router instance


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    
});
