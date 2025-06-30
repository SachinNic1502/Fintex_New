require('dotenv').config();
const http = require('http');
const app = require('./app');
const logger = require('./config/logger');
const { connectDB } = require('./config/database');

// Get port from environment and store in Express.
const port = process.env.PORT || 3000;
app.set('port', port);

// Create HTTP server.
const server = http.createServer(app);

// Connect to MongoDB
databaseConnection = async () => {
  try {
    await connectDB();
    logger.info('MongoDB connected');
    
    // Start the server after successful database connection
    server.listen(port, () => {
      logger.info(`Server running on port ${port} in ${process.env.NODE_ENV} mode`);
    });
  } catch (error) {
    logger.error('Failed to connect to MongoDB', error);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error(`Error: ${err.message}`);
  // Close server & exit process
  server.close(() => process.exit(1));
});

// Start the application
databaseConnection();
