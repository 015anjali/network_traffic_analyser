const Device = require('../models/MongoDevice');
const Flow = require('../models/MongoFlow');

class DeviceController {
  // Get all devices from MongoDB
  static async getAllDevices(req, res) {
    try {
      console.log('\n================== getAllDevices START ==================');
      console.log('📝 Attempting to fetch devices from MongoDB...');
      
      // Check if Device model is properly connected
      console.log('📌 Device Model:', Device.modelName);
      console.log('📌 Device Collection Name:', Device.collection.name);
      
      // Try to find devices
      const devices = await Device.find().sort({ registered_at: -1 });
      
      console.log('✅ Query executed successfully');
      console.log(`📊 Found ${devices.length} device(s) in database`);
      
      if (devices.length > 0) {
        console.log('📄 First device raw data:', JSON.stringify(devices[0], null, 2));
      }
      
      const formattedDevices = devices.map(d => ({
        device_id: d.device_id,
        device_name: d.device_name,
        ip_address: d.ip_address,
        status: d.status,
        last_seen: d.last_seen,
        total_flows: d.total_flows
      }));
      
      console.log('📤 Sending response with devices:', formattedDevices.length);
      console.log('================== getAllDevices END ==================\n');
      
      res.json({
        success: true,
        count: devices.length,
        devices: formattedDevices
      });
    } catch (error) {
      console.error('\n❌ ERROR in getAllDevices:');
      console.error('Error Message:', error.message);
      console.error('Error Stack:', error.stack);
      console.error('================== getAllDevices ERROR END ==================\n');
      
      res.status(500).json({
        success: false,
        error: 'Failed to fetch devices',
        details: error.message
      });
    }
  }

  // Get device by device_id with traffic classification summary
  static async getDeviceDetails(req, res) {
    try {
      const { device_id } = req.params;
      
      console.log('\n================== getDeviceDetails START ==================');
      console.log(`🔎 Fetching details for device_id: ${device_id}`);

      // Get device info
      const device = await Device.findOne({ device_id });
      console.log('✅ Device query executed');
      
      if (!device) {
        console.warn(`⚠️ Device not found for device_id: ${device_id}`);
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }
      
      console.log('📌 Device found:', device.device_name);

      // Get all flows for this device
      const flows = await Flow.find({ device_id }).lean();
      console.log(`📊 Found ${flows.length} flows for this device`);

      // Calculate classification summary
      const classificationSummary = {
        web: flows.filter(f => f.classification === 'Web').length,
        multimedia: flows.filter(f => f.classification === 'Multimedia').length,
        socialMedia: flows.filter(f => f.classification === 'Social Media').length,
        malicious: flows.filter(f => f.classification === 'Malicious').length,
        total: flows.length
      };
      
      console.log('📈 Classification Summary:', classificationSummary);

      // Calculate additional stats
      const stats = {
        totalBytes: flows.reduce((sum, f) => sum + (f.TotalBytes || 0), 0),
        totalPackets: flows.reduce((sum, f) => sum + (f.TotalPackets || 0), 0),
        protocols: this.getProtocolDistribution(flows),
        topDestinations: this.getTopDestinations(flows, 5)
      };
      
      console.log('💾 Stats calculated:', { totalBytes: stats.totalBytes, totalPackets: stats.totalPackets });
      console.log('================== getDeviceDetails END ==================\n');

      res.json({
        success: true,
        device: {
          device_id: device.device_id,
          device_name: device.device_name,
          ip_address: device.ip_address,
          status: device.status,
          last_seen: device.last_seen,
          registered_at: device.registered_at
        },
        classification: classificationSummary,
        stats
      });

    } catch (error) {
      console.error('\n❌ ERROR in getDeviceDetails:');
      console.error('Error Message:', error.message);
      console.error('Error Stack:', error.stack);
      console.error('================== getDeviceDetails ERROR END ==================\n');
      
      res.status(500).json({
        success: false,
        error: 'Failed to fetch device details',
        details: error.message
      });
    }
  }

  // Helper: Get protocol distribution
  static getProtocolDistribution(flows) {
    const distribution = {};
    flows.forEach(flow => {
      const protocol = flow.protocol || 'Unknown';
      distribution[protocol] = (distribution[protocol] || 0) + 1;
    });
    return distribution;
  }

  // Helper: Get top destination IPs
  static getTopDestinations(flows, limit = 5) {
    const destinations = {};
    flows.forEach(flow => {
      const dst = flow.dst_ip || 'Unknown';
      destinations[dst] = (destinations[dst] || 0) + 1;
    });
    
    return Object.entries(destinations)
      .sort(([, a], [, b]) => b - a)
      .slice(0, limit)
      .map(([ip, count]) => ({ ip, count }));
  }
}

module.exports = DeviceController;
