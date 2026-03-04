const mongoose = require('mongoose');
require('dotenv').config();

const mongoUri = process.env.MONGO_URI;
console.log('🔗 Connecting to MongoDB...');

mongoose.connect(mongoUri)
  .then(async () => {
    console.log('✅ MongoDB Connected\n');
    
    const db = mongoose.connection.db;
    
    // Clear existing data
    console.log('🗑️  Clearing existing data...');
    await db.collection('devices').deleteMany({});
    await db.collection('flows').deleteMany({});
    console.log('✅ Data cleared\n');
    
    // Insert device data (based on the screenshot: DESKTOP-JHDV6GL, 192.168.1.4)
    console.log('📝 Inserting device data...');
    const deviceResult = await db.collection('devices').insertOne({
      device_id: 'DESKTOP-JHDV6GL',
      device_name: 'DESKTOP-JHDV6GL',
      ip_address: '192.168.1.4',
      location: 'Office',
      last_seen: new Date(),
      registered_at: new Date('2025-02-01'),
      status: 'active',
      total_flows: 120
    });
    console.log('✅ Device inserted:', deviceResult.insertedId);
    
    // Insert sample flow data
    console.log('\n📝 Inserting sample flow data...');
    const flows = [
      // Web traffic
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '142.251.41.14', TotalBytes: 5000, TotalPackets: 25, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '173.194.73.94', TotalBytes: 3200, TotalPackets: 18, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '142.251.41.14', TotalBytes: 2800, TotalPackets: 15, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '34.117.59.81', TotalBytes: 4100, TotalPackets: 22, received_at: new Date() },
      
      // Multimedia traffic
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '185.230.35.32', TotalBytes: 15000, TotalPackets: 85, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '74.125.224.72', TotalBytes: 12000, TotalPackets: 75, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'UDP', src_ip: '192.168.1.4', dst_ip: '172.65.251.78', TotalBytes: 18000, TotalPackets: 120, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '208.67.222.123', TotalBytes: 9000, TotalPackets: 45, received_at: new Date() },
      
      // Social Media traffic
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Social Media', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '31.13.75.36', TotalBytes: 7000, TotalPackets: 50, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Social Media', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '199.232.68.133', TotalBytes: 5500, TotalPackets: 40, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Social Media', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '131.232.99.100', TotalBytes: 6200, TotalPackets: 48, received_at: new Date() },
      
      // Malicious traffic
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Malicious', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '10.0.0.1', TotalBytes: 2000, TotalPackets: 10, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Malicious', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '192.0.2.1', TotalBytes: 1500, TotalPackets: 8, received_at: new Date() },
      
      // More Web traffic
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '1.1.1.1', TotalBytes: 3500, TotalPackets: 20, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '8.8.8.8', TotalBytes: 4000, TotalPackets: 24, received_at: new Date() },
      
      // More Multimedia
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '185.230.36.32', TotalBytes: 16000, TotalPackets: 90, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'UDP', src_ip: '192.168.1.4', dst_ip: '172.65.251.79', TotalBytes: 20000, TotalPackets: 130, received_at: new Date() },
      
      // More Social Media
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Social Media', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '31.13.75.37', TotalBytes: 8000, TotalPackets: 55, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Social Media', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '199.232.68.134', TotalBytes: 6500, TotalPackets: 45, received_at: new Date() },
      
      // Additional traffic for variety
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Web', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '142.251.41.15', TotalBytes: 2900, TotalPackets: 16, received_at: new Date() },
      { device_id: 'DESKTOP-JHDV6GL', classification: 'Multimedia', protocol: 'TCP', src_ip: '192.168.1.4', dst_ip: '74.125.224.73', TotalBytes: 11000, TotalPackets: 70, received_at: new Date() }
    ];
    
    const flowResult = await db.collection('flows').insertMany(flows);
    console.log(`✅ ${flowResult.insertedCount} flows inserted\n`);
    
    // Verify data
    console.log('📊 Verification:');
    const deviceCount = await db.collection('devices').countDocuments();
    const flowCount = await db.collection('flows').countDocuments();
    console.log(`  ✅ Devices: ${deviceCount}`);
    console.log(`  ✅ Flows: ${flowCount}`);
    
    // Show summary by classification
    const pipeline = [
      {
        $group: {
          _id: '$classification',
          count: { $sum: 1 }
        }
      }
    ];
    const classification = await db.collection('flows').aggregate(pipeline).toArray();
    console.log('\n📈 Classification Summary:');
    classification.forEach(item => {
      console.log(`  - ${item._id}: ${item.count} flows`);
    });
    
    console.log('\n✅ Database seeded successfully!');
    mongoose.disconnect();
  })
  .catch(err => {
    console.error('❌ Error:', err.message);
    mongoose.disconnect();
    process.exit(1);
  });

setTimeout(() => {
  mongoose.disconnect();
  process.exit(0);
}, 20000);
