const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs-extra');
const pythonClient = require('./services/pythonClient'); // <-- added

// Import routes
const sessionRoutes = require('./routes/sessions');
const flowRoutes = require('./routes/flows');
const deviceRoutes = require('./routes/devices');

const app = express();

// Global request logging middleware (FIRST - before everything)
app.use((req, res, next) => {
  console.log(`\n[${new Date().toISOString()}] 📬 ${req.method} ${req.path}`);
  console.log('   Query:', req.query);
  console.log('   Headers:', req.headers.host);
  next();
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:3000'
  ],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static file serving for uploads
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// API Routes
console.log('🔌 Registering API routes...');
app.use('/api/sessions', sessionRoutes);
console.log('✅ Sessions routes registered at /api/sessions');
app.use('/api/flows', flowRoutes);
console.log('✅ Flows routes registered at /api/flows');
app.use('/api/devices', deviceRoutes);
console.log('✅ Devices routes registered at /api/devices');

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// --- Multer storage setup ---
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', 'uploads');
    await fs.ensureDir(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}_${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.pcap', '.pcapng'];
    const fileExtension = path.extname(file.originalname).toLowerCase();
    if (allowedExtensions.includes(fileExtension)) {
      cb(null, true);
    } else {
      cb(new Error('Only .pcap and .pcapng files are allowed'), false);
    }
  }
});

// --- Upload & Analyze PCAP ---
app.post('/api/upload', upload.single('pcap'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const uploadId = uuidv4();
    const filePath = req.file.path;

    // Call Python client to analyze PCAP
    const analysisResult = await pythonClient.analyzePcapFile(filePath, uploadId);

    // Return upload info + analysis
    res.json({
      success: true,
      uploadId,
      filename: req.file.originalname,
      size: req.file.size,
      filePath,
      analysis: analysisResult, // flows and stats from Python
      message: 'File uploaded and analyzed successfully'
    });

  } catch (error) {
    console.error('Upload/Analysis error:', error);
    res.status(500).json({ error: 'Upload/analysis failed', details: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
    }
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error', details: error.message });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

module.exports = app;
