import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Loader, AlertCircle } from 'lucide-react';
import { apiService } from '../services/api';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';
import { Bar, Pie } from 'react-chartjs-2';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const DeviceDetails = () => {
  const { device_id } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deviceData, setDeviceData] = useState(null);

  useEffect(() => {
    fetchDeviceDetails();
  }, [device_id]);

  const fetchDeviceDetails = async () => {
    try {
      setLoading(true);
      const response = await apiService.getDeviceDetails(device_id);
      if (response.success) {
        setDeviceData(response);
      }
    } catch (err) {
      console.error('Error fetching device details:', err);
      setError(err.message || 'Failed to fetch device details');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center">
          <Loader className="animate-spin text-purple-400 mx-auto mb-4" size={40} />
          <p className="text-gray-300">Loading device details...</p>
        </motion.div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
        <div className="max-w-4xl mx-auto">
          <button
            onClick={() => navigate('/devices')}
            className="flex items-center text-purple-400 hover:text-purple-300 mb-8 transition-colors"
          >
            <ArrowLeft size={20} className="mr-2" />
            Back to Devices
          </button>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-red-500/20 border border-red-500 rounded-lg p-6"
          >
            <div className="flex items-start">
              <AlertCircle className="text-red-400 mr-4 mt-1" size={24} />
              <div>
                <p className="text-red-300 text-lg font-semibold">Error</p>
                <p className="text-red-200 mt-2">{error}</p>
                <button
                  onClick={fetchDeviceDetails}
                  className="mt-4 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
                >
                  Retry
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  if (!deviceData) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
        <p className="text-gray-300">No data available</p>
      </div>
    );
  }

  const { device, classification, stats } = deviceData;

  // Prepare chart data
  const classificationChartData = {
    labels: ['Web', 'Multimedia', 'Social Media', 'Malicious'],
    datasets: [
      {
        label: 'Traffic Classification',
        data: [
          classification.web,
          classification.multimedia,
          classification.socialMedia,
          classification.malicious
        ],
        backgroundColor: [
          'rgba(59, 130, 246, 0.8)',    // blue
          'rgba(249, 115, 22, 0.8)',    // orange
          'rgba(168, 85, 247, 0.8)',    // purple
          'rgba(239, 68, 68, 0.8)'      // red
        ],
        borderColor: [
          'rgba(59, 130, 246, 1)',
          'rgba(249, 115, 22, 1)',
          'rgba(168, 85, 247, 1)',
          'rgba(239, 68, 68, 1)'
        ],
        borderWidth: 2
      }
    ]
  };

  const protocolChartData = {
    labels: Object.keys(stats.protocols),
    datasets: [
      {
        label: 'Protocol Distribution',
        data: Object.values(stats.protocols),
        backgroundColor: 'rgba(168, 85, 247, 0.8)',
        borderColor: 'rgba(168, 85, 247, 1)',
        borderWidth: 2
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        labels: {
          color: '#e5e7eb'
        }
      }
    },
    scales: {
      y: {
        ticks: {
          color: '#e5e7eb'
        },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)'
        }
      },
      x: {
        ticks: {
          color: '#e5e7eb'
        },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)'
        }
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-6xl mx-auto">
        {/* Back Button */}
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          onClick={() => navigate('/devices')}
          className="flex items-center text-purple-400 hover:text-purple-300 mb-8 transition-colors"
        >
          <ArrowLeft size={20} className="mr-2" />
          Back to Devices
        </motion.button>

        {/* Device Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gradient-to-r from-slate-800 to-slate-700 rounded-lg p-8 mb-8"
        >
          <h1 className="text-4xl font-bold text-white mb-2">{device.device_name}</h1>
          <p className="text-gray-300 mb-4">{device.ip_address}</p>
          <div className="flex flex-wrap gap-6">
            <div>
              <p className="text-gray-400 text-sm">Status</p>
              <p className="text-white font-semibold capitalize">{device.status}</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Last Seen</p>
              <p className="text-white font-semibold">
                {new Date(device.last_seen).toLocaleDateString()}
              </p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Registered</p>
              <p className="text-white font-semibold">
                {new Date(device.registered_at).toLocaleDateString()}
              </p>
            </div>
          </div>
        </motion.div>

        {/* Key Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"
        >
          <div className="bg-slate-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm mb-2">Total Flows</p>
            <p className="text-3xl font-bold text-purple-300">{classification.total}</p>
          </div>
          <div className="bg-slate-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm mb-2">Total Bytes</p>
            <p className="text-3xl font-bold text-blue-300">
              {(stats.totalBytes / 1024 / 1024).toFixed(2)} MB
            </p>
          </div>
          <div className="bg-slate-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm mb-2">Total Packets</p>
            <p className="text-3xl font-bold text-green-300">{stats.totalPackets}</p>
          </div>
        </motion.div>

        {/* Charts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8"
        >
          {/* Classification Chart */}
          <div className="bg-slate-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">Traffic Classification</h2>
            <div className="h-72 flex items-center justify-center">
              <Pie
                data={classificationChartData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      labels: { color: '#e5e7eb' }
                    }
                  }
                }}
              />
            </div>
          </div>

          {/* Protocol Distribution */}
          <div className="bg-slate-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">Protocol Distribution</h2>
            <div className="h-72">
              <Bar data={protocolChartData} options={chartOptions} />
            </div>
          </div>
        </motion.div>

        {/* Classification Breakdown */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-800 rounded-lg p-6"
        >
          <h2 className="text-xl font-bold text-white mb-6">Classification Breakdown</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">Web</div>
              <div className="text-2xl font-bold text-blue-400">{classification.web}</div>
              <div className="text-xs text-gray-500 mt-1">
                {((classification.web / classification.total) * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">Multimedia</div>
              <div className="text-2xl font-bold text-orange-400">{classification.multimedia}</div>
              <div className="text-xs text-gray-500 mt-1">
                {((classification.multimedia / classification.total) * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">Social Media</div>
              <div className="text-2xl font-bold text-purple-400">{classification.socialMedia}</div>
              <div className="text-xs text-gray-500 mt-1">
                {((classification.socialMedia / classification.total) * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">Malicious</div>
              <div className="text-2xl font-bold text-red-400">{classification.malicious}</div>
              <div className="text-xs text-gray-500 mt-1">
                {((classification.malicious / classification.total) * 100).toFixed(1)}%
              </div>
            </div>
          </div>
        </motion.div>

        {/* Top Destinations */}
        {stats.topDestinations && stats.topDestinations.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-slate-800 rounded-lg p-6 mt-8"
          >
            <h2 className="text-xl font-bold text-white mb-6">Top Destination IPs</h2>
            <div className="space-y-3">
              {stats.topDestinations.map((dest, idx) => (
                <div key={idx} className="flex items-center justify-between bg-slate-700 p-4 rounded-lg">
                  <span className="text-gray-300">{dest.ip}</span>
                  <span className="text-purple-300 font-semibold">{dest.count} flows</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default DeviceDetails;
