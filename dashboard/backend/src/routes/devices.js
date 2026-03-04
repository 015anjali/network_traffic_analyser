const express = require('express');
const DeviceController = require('../controllers/deviceController');

const router = express.Router();

// Logging middleware
router.use((req, res, next) => {
  console.log(`📍 Device Route Hit: ${req.method} ${req.path}`);
  next();
});

// Get all devices
router.get('/', (req, res, next) => {
  console.log('🔍 Getting all devices...');
  DeviceController.getAllDevices(req, res).catch(next);
});

// Get device details with traffic classification by device_id
router.get('/:device_id', (req, res, next) => {
  console.log(`🔍 Getting device details for: ${req.params.device_id}`);
  DeviceController.getDeviceDetails(req, res).catch(next);
});

module.exports = router;
