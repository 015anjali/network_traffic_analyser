import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { 
  Activity, 
  Upload, 
  Shield, 
  TrendingUp, 
  Network, 
  Clock,
  ArrowRight,
  Server 
} from 'lucide-react';

const Home = () => {
  const stats = [
    { label: 'Active Sessions', value: '3', icon: Activity, color: 'from-green-500 to-emerald-600' },
    { label: 'Total Flows', value: '1,247', icon: Network, color: 'from-blue-500 to-cyan-600' },
    { label: 'Threats Detected', value: '12', icon: Shield, color: 'from-red-500 to-pink-600' },
    { label: 'Uptime', value: '99.9%', icon: Clock, color: 'from-purple-500 to-violet-600' },
  ];

  const quickActions = [
    {
      title: 'Start Live Capture',
      description: 'Monitor real-time network traffic',
      icon: Activity,
      link: '/live',
      color: 'from-green-500 to-emerald-600'
    },
    {
      title: 'Upload PCAP File',
      description: 'Analyze existing packet captures',
      icon: Upload,
      link: '/upload',
      color: 'from-blue-500 to-cyan-600'
    },
    {
      title: 'View Devices',
      description: 'Explore traffic by network device',
      icon: Server,
      link: '/devices',
      color: 'from-purple-500 to-violet-600'
    }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="min-h-screen p-6"
    >
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-2">
            Network Traffic Classification Dashboard
          </h1>
          <p className="text-purple-300 text-lg">
            Monitor, analyze, and classify network flows in real-time
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-purple-500/20"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-purple-300 text-sm font-medium">{stat.label}</p>
                  <p className="text-white text-3xl font-bold mt-1">{stat.value}</p>
                </div>
                <div className={`p-3 rounded-xl bg-gradient-to-r ${stat.color}`}>
                  <stat.icon className="h-6 w-6 text-white" />
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          {quickActions.map((action, index) => (
            <motion.div
              key={action.title}
              initial={{ opacity: 0, x: index % 2 === 0 ? -20 : 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 + index * 0.1 }}
            >
              <Link to={action.link}>
                <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 border border-purple-500/20 hover:border-purple-400/40 transition-all group cursor-pointer">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className={`p-4 rounded-xl bg-gradient-to-r ${action.color} w-fit mb-4`}>
                        <action.icon className="h-8 w-8 text-white" />
                      </div>
                      <h3 className="text-2xl font-bold text-white mb-2">{action.title}</h3>
                      <p className="text-purple-300 text-lg">{action.description}</p>
                    </div>
                    <ArrowRight className="h-6 w-6 text-purple-400 group-hover:text-white group-hover:translate-x-1 transition-all" />
                  </div>
                </div>
              </Link>
            </motion.div>
          ))}
        </div>

        {/* System Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 border border-purple-500/20"
        >
          <h2 className="text-2xl font-bold text-white mb-6 flex items-center">
            <TrendingUp className="h-6 w-6 mr-3 text-purple-400" />
            System Status
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="w-16 h-16 bg-gradient-to-r from-green-500 to-emerald-600 rounded-full flex items-center justify-center mx-auto mb-3">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-1">Classification Engine</h3>
              <p className="text-green-400 font-medium">Online</p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-cyan-600 rounded-full flex items-center justify-center mx-auto mb-3">
                <Network className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-1">Network Monitor</h3>
              <p className="text-blue-400 font-medium">Active</p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-gradient-to-r from-purple-500 to-violet-600 rounded-full flex items-center justify-center mx-auto mb-3">
                <Activity className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-1">Data Processing</h3>
              <p className="text-purple-400 font-medium">Ready</p>
            </div>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
};

export default Home;