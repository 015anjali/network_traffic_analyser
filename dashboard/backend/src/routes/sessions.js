const express = require('express');
const { v4: uuidv4 } = require('uuid');
const SessionController = require('../controllers/sessionController');

const router = express.Router();

// Start a new live capture session
// delegate heavy lifting to controller
router.post('/start', SessionController.startSession);

// Stop a live capture session
router.post('/:sessionId/stop', SessionController.stopSession);

// Get session information
router.get('/:sessionId', SessionController.getSession);

// Get all sessions
router.get('/', SessionController.getAllSessions);

// Analyze uploaded PCAP file
router.post('/analyze/:uploadId', SessionController.analyzePcap);

module.exports = router;