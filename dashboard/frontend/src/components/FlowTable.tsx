// import React from 'react';
// import { motion } from 'framer-motion';
// import { Shield, AlertTriangle, Globe, Play, Users } from 'lucide-react';

// const FlowTable = ({ flows }) => {
//   const getClassIcon = (prediction) => {
//     switch (prediction) {
//       case 'Web':
//         return <Globe className="h-4 w-4 text-green-400" />;
//       case 'Multimedia':
//         return <Play className="h-4 w-4 text-blue-400" />;
//       case 'Social Media':
//         return <Users className="h-4 w-4 text-yellow-400" />;
//       case 'Malicious':
//         return <AlertTriangle className="h-4 w-4 text-red-400" />;
//       default:
//         return <Shield className="h-4 w-4 text-purple-400" />;
//     }
//   };

//   const getClassColor = (prediction) => {
//     switch (prediction) {
//       case 'Web':
//         return 'bg-green-900/20 text-green-400 border-green-500/30';
//       case 'Multimedia':
//         return 'bg-blue-900/20 text-blue-400 border-blue-500/30';
//       case 'Social Media':
//         return 'bg-yellow-900/20 text-yellow-400 border-yellow-500/30';
//       case 'Malicious':
//         return 'bg-red-900/20 text-red-400 border-red-500/30';
//       default:
//         return 'bg-purple-900/20 text-purple-400 border-purple-500/30';
//     }
//   };

//   const formatBytes = (bytes) => {
//     if (bytes === 0) return '0 B';
//     const k = 1024;
//     const sizes = ['B', 'KB', 'MB'];
//     const i = Math.floor(Math.log(bytes) / Math.log(k));
//     return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
//   };

//   if (!flows || flows.length === 0) {
//     return (
//       <div className="text-center py-8">
//         <Shield className="h-12 w-12 text-purple-400 mx-auto mb-3" />
//         <p className="text-purple-300">No flow data available</p>
//       </div>
//     );
//   }

//   return (
//     <div className="overflow-x-auto">
//       <table className="w-full">
//         <thead>
//           <tr className="border-b border-purple-500/20">
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Source
//             </th>
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Destination
//             </th>
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Protocol
//             </th>
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Classification
//             </th>
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Data
//             </th>
//             <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
//               Domain/URL
//             </th>
//           </tr>
//         </thead>
//         <tbody className="divide-y divide-purple-500/10">
//           {flows.map((flow, index) => (
//             <motion.tr
//               key={flow.id || index}
//               initial={{ opacity: 0, x: -20 }}
//               animate={{ opacity: 1, x: 0 }}
//               transition={{ delay: index * 0.1 }}
//               className="hover:bg-slate-700/30 transition-colors"
//             >
//               <td className="py-3">
//                 <div className="text-sm">
//                   <div className="text-white font-medium">{flow.srcIP}</div>
//                   <div className="text-purple-400 text-xs">:{flow.srcPort}</div>
//                 </div>
//               </td>
//               <td className="py-3">
//                 <div className="text-sm">
//                   <div className="text-white font-medium">{flow.dstIP}</div>
//                   <div className="text-purple-400 text-xs">:{flow.dstPort}</div>
//                 </div>
//               </td>
//               <td className="py-3">
//                 <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-slate-700/50 text-purple-300 border border-purple-500/30">
//                   {flow.protocol}
//                 </span>
//               </td>
//               <td className="py-3">
//                 <div className={`inline-flex items-center space-x-1 px-2 py-1 rounded-md text-xs font-medium border ${getClassColor(flow.prediction)}`}>
//                   {getClassIcon(flow.prediction)}
//                   <span>{flow.prediction}</span>
//                 </div>
//               </td>
//               <td className="py-3">
//                 <div className="text-sm text-purple-300">
//                   <div>{formatBytes(flow.bytes || 0)}</div>
//                   <div className="text-xs text-purple-400">{flow.packets || 0} pkts</div>
//                 </div>
//               </td>
//             </motion.tr>
//           ))}
//         </tbody>
//       </table>
//     </div>
//   );
// };

// export default FlowTable;


import React from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Globe, Play, Users } from 'lucide-react';

// Define the type for a flow object
interface Flow {
  id?: string | number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  prediction: string;
  bytes?: number;
  packets?: number;
  URLs?: string;
  urls?: string;
}

// Define the props type
interface FlowTableProps {
  flows: Flow[];
}

const FlowTable = ({ flows }: FlowTableProps) => {
  const getClassIcon = (prediction: string) => {
    switch (prediction) {
      case 'Web':
        return <Globe className="h-4 w-4 text-green-400" />;
      case 'Multimedia':
        return <Play className="h-4 w-4 text-blue-400" />;
      case 'Social Media':
        return <Users className="h-4 w-4 text-yellow-400" />;
      case 'Malicious':
        return <AlertTriangle className="h-4 w-4 text-red-400" />;
      default:
        return <Shield className="h-4 w-4 text-purple-400" />;
    }
  };

  const getClassColor = (prediction: string) => {
    switch (prediction) {
      case 'Web':
        return 'bg-green-900/20 text-green-400 border-green-500/30';
      case 'Multimedia':
        return 'bg-blue-900/20 text-blue-400 border-blue-500/30';
      case 'Social Media':
        return 'bg-yellow-900/20 text-yellow-400 border-yellow-500/30';
      case 'Malicious':
        return 'bg-red-900/20 text-red-400 border-red-500/30';
      default:
        return 'bg-purple-900/20 text-purple-400 border-purple-500/30';
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  if (!flows || flows.length === 0) {
    return (
      <div className="text-center py-8">
        <Shield className="h-12 w-12 text-purple-400 mx-auto mb-3" />
        <p className="text-purple-300">No flow data available</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-purple-500/20">
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Source
            </th>
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Destination
            </th>
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Protocol
            </th>
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Classification
            </th>
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Data
            </th>
            <th className="text-left py-3 text-xs font-medium text-purple-300 uppercase tracking-wider">
              Domain/URL
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-purple-500/10">
          {flows.map((flow, index) => (
            <motion.tr
              key={flow.id || index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="hover:bg-slate-700/30 transition-colors"
            >
              <td className="py-3">
                <div className="text-sm">
                  <div className="text-white font-medium">{flow.srcIP}</div>
                  <div className="text-purple-400 text-xs">:{flow.srcPort}</div>
                </div>
              </td>
              <td className="py-3">
                <div className="text-sm">
                  <div className="text-white font-medium">{flow.dstIP}</div>
                  <div className="text-purple-400 text-xs">:{flow.dstPort}</div>
                </div>
              </td>
              <td className="py-3">
                <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-slate-700/50 text-purple-300 border border-purple-500/30">
                  {flow.protocol}
                </span>
              </td>
              <td className="py-3">
                <div className={`inline-flex items-center space-x-1 px-2 py-1 rounded-md text-xs font-medium border ${getClassColor(flow.prediction)}`}>
                  {getClassIcon(flow.prediction)}
                  <span>{flow.prediction}</span>
                </div>
              </td>
              <td className="py-3">
                <div className="text-sm text-purple-300">
                  <div>{formatBytes(flow.bytes || 0)}</div>
                  <div className="text-xs text-purple-400">{flow.packets || 0} pkts</div>
                </div>
              </td>
              <td className="py-3">
                <div className="text-sm">
                  <div className="text-white font-medium max-w-xs truncate" title={flow.URLs || flow.urls || ''}>
                    {flow.URLs || flow.urls || 'N/A'}
                  </div>
                </div>
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FlowTable;