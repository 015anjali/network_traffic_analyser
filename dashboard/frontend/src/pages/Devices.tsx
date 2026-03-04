import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, Loader } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';

const Devices = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    console.log('🔄 Devices component mounted, fetching devices...');
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      console.log('📡 Calling getAllDevices() from apiService...');
      setLoading(true);
      const response = await apiService.getAllDevices();
      console.log('✅ API Response received:', response);
      if (response.success) {
        console.log('📊 Setting devices:', response.devices);
        setDevices(response.devices);
      } else {
        console.warn('⚠️ API response not successful');
        setError('API returned non-success status');
      }
    } catch (err) {
      console.error('❌ Error fetching devices:', err);
      setError(err.message || 'Failed to fetch devices');
    } finally {
      setLoading(false);
    }
  };

  const handleDeviceClick = (device_id) => {
    navigate(`/devices/${device_id}`);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-12"
        >
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-2">
            Network Devices
          </h1>
          <p className="text-gray-300 text-lg">
            Monitor and analyze traffic from registered network devices
          </p>
        </motion.div>

        {/* Error State */}
        {error && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-red-500/20 border border-red-500 rounded-lg p-4 mb-8"
          >
            <p className="text-red-300">{error}</p>
            <button
              onClick={fetchDevices}
              className="mt-4 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
            >
              Retry
            </button>
          </motion.div>
        )}

        {/* Loading State */}
        {loading ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center h-96"
          >
            <Loader className="animate-spin text-purple-400 mr-3" size={32} />
            <p className="text-gray-300 text-lg">Loading devices...</p>
          </motion.div>
        ) : devices.length === 0 ? (
          // Empty State
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-slate-800 rounded-lg p-12 text-center"
          >
            <p className="text-gray-400 text-lg">No devices found</p>
          </motion.div>
        ) : (
          // Devices Grid
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ staggerChildren: 0.1 }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {devices.map((device, idx) => (
              <motion.div
                key={device.device_id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.1 }}
                onClick={() => handleDeviceClick(device.device_id)}
                className="bg-gradient-to-br from-slate-700 to-slate-800 rounded-lg p-6 cursor-pointer hover:shadow-xl hover:shadow-purple-500/20 transition-all transform hover:scale-105"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-white mb-1">
                      {device.device_name}
                    </h3>
                    <p className="text-sm text-gray-400">{device.ip_address}</p>
                  </div>
                  <ArrowRight className="text-purple-400 mt-1" size={20} />
                </div>

                {/* Status Badge */}
                <div className="mb-4">
                  <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${
                    device.status === 'active'
                      ? 'bg-green-500/20 text-green-300'
                      : 'bg-gray-600/20 text-gray-300'
                  }`}>
                    {device.status || 'Unknown'}
                  </span>
                </div>

                {/* Stats */}
                <div className="space-y-2 text-sm text-gray-300 border-t border-slate-600 pt-4">
                  <div className="flex justify-between">
                    <span>Total Flows:</span>
                    <span className="font-semibold text-purple-300">{device.total_flows || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Last Seen:</span>
                    <span className="font-semibold text-purple-300">
                      {device.last_seen
                        ? new Date(device.last_seen).toLocaleDateString()
                        : 'N/A'}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default Devices;
