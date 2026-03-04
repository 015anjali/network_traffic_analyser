const mongoose = require('mongoose');

// This schema exactly matches the Python insertion into the 'flow_classifier' DB
const flowSchema = new mongoose.Schema({
    device_id: String,
    received_at: Date,
    server_timestamp: String,
    processed: Boolean,
    classification: String,
    src_ip: String,
    dst_ip: String,
    src_port: Number,
    dst_port: Number,
    protocol: String,
    TotalBytes: Number,
    TotalPackets: Number,
    URLs: String,
    timestamp: String,
    flow_id: String
}, {
    // Keep strict false to allow dynamic fields from the python analyzer
    strict: false,
    collection: 'flows'
});

const Flow = mongoose.model('Flow', flowSchema);

module.exports = Flow;
