const express = require('express');
const FlowReportController = require('../controllers/flowReportController');

const router = express.Router();

// delegate to controller methods for clarity and reuse
router.get('/:sessionId', FlowReportController.getFlows);
router.get('/:sessionId/stats', FlowReportController.getFlowStats);
router.get('/:sessionId/suspicious', FlowReportController.getSuspiciousFlows);
router.get('/:sessionId/realtime', FlowReportController.getRealtimeFlows);

module.exports = router;
