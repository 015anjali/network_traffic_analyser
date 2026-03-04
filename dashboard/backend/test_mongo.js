const mongoose = require('mongoose');
require('dotenv').config();

const mongoUri = process.env.MONGO_URI;
console.log('🔗 Connecting to MongoDB:', mongoUri.substring(0, 50) + '...');

mongoose.connect(mongoUri)
  .then(async () => {
    console.log('✅ MongoDB Connected');
    
    // Get database
    const db = mongoose.connection.db;
    console.log('\n📚 Listing all collections...\n');
    
    const collections = await db.listCollections().toArray();
    console.log(`Found ${collections.length} collections:`);
    collections.forEach(col => console.log(`  - ${col.name}`));
    
    // Check devices collection
    console.log('\n🔍 Checking "devices" collection:');
    const devicesCount = await db.collection('devices').countDocuments();
    console.log(`  Documents: ${devicesCount}`);
    
    if (devicesCount > 0) {
      const devices = await db.collection('devices').find({}).toArray();
      console.log('  Data:', JSON.stringify(devices, null, 2));
    }
    
    // Check flows collection
    console.log('\n🔍 Checking "flows" collection:');
    const flowsCount = await db.collection('flows').countDocuments();
    console.log(`  Documents: ${flowsCount}`);
    
    if (flowsCount > 0) {
      const sample = await db.collection('flows').findOne({});
      console.log('  Sample flow:', JSON.stringify(sample, null, 2));
    }
    
    // Check for any device-related collections
    console.log('\n🔍 Checking other collections:');
    for (const col of collections) {
      if (col.name.toLowerCase().includes('device') || col.name.toLowerCase().includes('dev')) {
        const count = await db.collection(col.name).countDocuments();
        console.log(`  ${col.name}: ${count} documents`);
      }
    }
    
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
}, 15000);
