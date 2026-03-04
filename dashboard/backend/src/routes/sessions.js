const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pythonClient = require('../services/pythonClient');

const router = express.Router();

// Start a new live capture session
router.post('/start', async (req, res) => {
  try {
    const sessionId = uuidv4();
    const config = req.body || {};

    const result = await pythonClient.startLiveCapture(sessionId, config);

    res.json({
      success: true,
      sessionId,
      message: 'Live capture session started',
      config
    });

  } catch (error) {
    console.error('Error starting session:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to start live capture session',
      details: error.message
    });
  }
});

// Stop a live capture session
router.post('/:sessionId/stop', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const result = await pythonClient.stopLiveCapture(sessionId);

    res.json({
      success: true,
      sessionId,
      message: 'Live capture session stopped'
    });

  } catch (error) {
    console.error('Error stopping session:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to stop live capture session',
      details: error.message
    });
  }
});

// Get session information
router.get('/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const sessionInfo = pythonClient.getSessionInfo(sessionId);

    if (!sessionInfo) {
      return res.status(404).json({
        success: false,
        error: 'Session not found'
      });
    }

    res.json({
      success: true,
      session: sessionInfo
    });

  } catch (error) {
    console.error('Error getting session info:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get session information',
      details: error.message
    });
  }
});

// Postman Polling Endpoint for Live Data
router.get('/:sessionId/live-flows', async (req, res) => {
  try {
    const { sessionId } = req.params;

    // Calls the updated MongoDB-based function
    const result = await pythonClient.getLiveFlows(sessionId);

    res.json({
      success: true,
      sessionId,
      data: result
    });

  } catch (error) {
    console.error('Error polling live flows:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to poll live flows',
      details: error.message
    });
  }
});

// Get all sessions
router.get('/', (req, res) => {
  try {
    const sessions = pythonClient.getAllSessions();

    res.json({
      success: true,
      sessions
    });

  } catch (error) {
    console.error('Error getting sessions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get sessions',
      details: error.message
    });
  }
});

// Analyze uploaded PCAP file
router.post('/analyze/:uploadId', async (req, res) => {
  try {
    const { uploadId } = req.params;
    const { filePath } = req.body;

    if (!filePath) {
      return res.status(400).json({
        success: false,
        error: 'File path is required'
      });
    }

    const result = await pythonClient.analyzePcapFile(filePath, uploadId);

    res.json({
      success: true,
      uploadId,
      analysis: result
    });

  } catch (error) {
    console.error('Error analyzing PCAP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to analyze PCAP file',
      details: error.message
    });
  }
});

module.exports = router;