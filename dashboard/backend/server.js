// load environment variables from .env (if present)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs-extra');

const app = require('./src/app');
const connectDB = require('./src/config/db');

const PORT = process.env.PORT || 3001;

// log environment-derived configuration for debugging
console.log('Using PORT =', PORT);
console.log('Using MONGO_URI =', process.env.MONGO_URI);

// Create HTTP server
const server = http.createServer(app);

// Create WebSocket server for real-time updates
const wss = new WebSocket.Server({ server });

// Store WebSocket connections
global.wsConnections = new Set();

wss.on('connection', (ws) => {
  console.log('New WebSocket connection established');
  global.wsConnections.add(ws);

  ws.on('close', () => {
    console.log('WebSocket connection closed');
    global.wsConnections.delete(ws);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    global.wsConnections.delete(ws);
  });
});

// Broadcast function for real-time updates
global.broadcast = (data) => {
  const message = JSON.stringify(data);
  global.wsConnections.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
};

// Ensure required directories exist
const ensureDirectories = async () => {
  const dirs = [
    path.join(__dirname, '..', 'data'),
    path.join(__dirname, '..', 'models'),
    path.join(__dirname, 'uploads')
  ];

  for (const dir of dirs) {
    await fs.ensureDir(dir);
  }
};

// Start server
const startServer = async () => {
  try {
    await connectDB(); // Connected to MongoDB
    await ensureDirectories();

    server.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📡 WebSocket server ready for real-time updates`);
      console.log(`🔗 API endpoints available at http://localhost:${PORT}/api`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});