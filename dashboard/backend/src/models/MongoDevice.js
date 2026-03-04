const mongoose = require('mongoose');

// Schema matching the devices collection structure from MongoDB
const deviceSchema = new mongoose.Schema({
    device_id: String,
    device_name: String,
    ip_address: String,
    location: String,
    last_seen: Date,
    registered_at: Date,
    status: String,
    total_flows: Number
}, {
    strict: false,
    collection: 'devices'
});

const Device = mongoose.model('Device', deviceSchema);

module.exports = Device;
