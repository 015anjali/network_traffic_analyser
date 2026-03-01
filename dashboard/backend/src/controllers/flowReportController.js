const pythonClient = require('../services/pythonClient');
const FlowRecord = require('../models/FlowRecord');

// Controller for flow reports extracted during live capture or analysis.
// Provides endpoints for pagination, statistics, suspicious flows, and
// realtime updates.  Renamed from "FlowsController" for clarity.
class FlowReportController {
  // Get flows for a specific session
  static async getFlows(req, res) {
    try {
      const { sessionId } = req.params;
      const { 
        lastNSeconds, 
        limit = 100, 
        offset = 0,
        classification 
      } = req.query;

      const lastN = lastNSeconds ? parseInt(lastNSeconds) : null;
      const result = await pythonClient.getLiveFlows(sessionId, lastN);

      // Convert to FlowRecord objects
      let flows = result.flows.map(flowData => new FlowRecord(flowData));

      // Filter by classification if specified
      if (classification && classification !== 'all') {
        flows = flows.filter(flow => 
          flow.prediction.toLowerCase() === classification.toLowerCase()
        );
      }

      // Apply pagination
      const totalFlows = flows.length;
      const paginatedFlows = flows
        .slice(parseInt(offset), parseInt(offset) + parseInt(limit))
        .map(flow => flow.toJSON());

      res.json({
        success: true,
        sessionId,
        flows: paginatedFlows,
        stats: result.stats,
        pagination: {
          total: totalFlows,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: parseInt(offset) + parseInt(limit) < totalFlows
        }
      });

    } catch (error) {
      console.error('Error getting flows:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get flows',
        details: error.message
      });
    }
  }

  // Get flow statistics for a session
  static async getFlowStats(req, res) {
    try {
      const { sessionId } = req.params;
      const { lastNSeconds } = req.query;

      const lastN = lastNSeconds ? parseInt(lastNSeconds) : null;
      const result = await pythonClient.getLiveFlows(sessionId, lastN);

      // Enhanced statistics
      const flows = result.flows.map(flowData => new FlowRecord(flowData));
      const stats = {
        ...result.stats,
        totalBytes: flows.reduce((sum, flow) => sum + flow.totalBytes, 0),
        totalPackets: flows.reduce((sum, flow) => sum + flow.totalPackets, 0),
        avgDuration: flows.length > 0 ? 
          flows.reduce((sum, flow) => sum + flow.duration, 0) / flows.length : 0,
        suspiciousFlows: flows.filter(flow => flow.isSuspicious()).length,
        protocolDistribution: this.getProtocolDistribution(flows),
        topSources: this.getTopSources(flows, 5),
        topDestinations: this.getTopDestinations(flows, 5)
      };

      res.json({
        success: true,
        sessionId,
        stats,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Error getting flow stats:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get flow statistics',
        details: error.message
      });
    }
  }

  // Get suspicious flows
  static async getSuspiciousFlows(req, res) {
    try {
      const { sessionId } = req.params;
      const { limit = 50 } = req.query;

      const result = await pythonClient.getLiveFlows(sessionId);
      const flows = result.flows
        .map(flowData => new FlowRecord(flowData))
        .filter(flow => flow.isSuspicious())
        .slice(0, parseInt(limit))
        .map(flow => flow.toJSON());

      res.json({
        success: true,
        sessionId,
        suspiciousFlows: flows,
        count: flows.length
      });

    } catch (error) {
      console.error('Error getting suspicious flows:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get suspicious flows',
        details: error.message
      });
    }
  }

  // Get real-time flow updates (for WebSocket alternative)
  static async getRealtimeFlows(req, res) {
    try {
      const { sessionId } = req.params;
      const { since } = req.query; // Timestamp to get flows since

      const result = await pythonClient.getLiveFlows(sessionId, 30); // Last 30 seconds
      let flows = result.flows.map(flowData => new FlowRecord(flowData));

      // Filter flows since timestamp if provided
      if (since) {
        const sinceDate = new Date(since);
        flows = flows.filter(flow => new Date(flow.timestamp) > sinceDate);
      }

      res.json({
        success: true,
        sessionId,
        flows: flows.slice(-20).map(flow => flow.toJSON()), // Last 20 flows
        stats: result.stats,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Error getting realtime flows:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get realtime flows',
        details: error.message
      });
    }
  }

  // Helper method to get protocol distribution
  static getProtocolDistribution(flows) {
    const distribution = {};
    flows.forEach(flow => {
      distribution[flow.protocol] = (distribution[flow.protocol] || 0) + 1;
    });
    return distribution;
  }

  // Helper method to get top source IPs
  static getTopSources(flows, limit = 5) {
    const sources = {};
    flows.forEach(flow => {
      sources[flow.srcIP] = (sources[flow.srcIP] || 0) + 1;
    });
    
    return Object.entries(sources)
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([ip, count]) => ({ ip, count }));
  }

  // Helper method to get top destination IPs
  static getTopDestinations(flows, limit = 5) {
    const destinations = {};
    flows.forEach(flow => {
      destinations[flow.dstIP] = (destinations[flow.dstIP] || 0) + 1;
    });
    
    return Object.entries(destinations)
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([ip, count]) => ({ ip, count }));
  }
}

module.exports = FlowReportController;
