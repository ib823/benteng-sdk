import { useQuery } from '@tanstack/react-query';
import { Activity, Shield, AlertCircle, CheckCircle } from 'lucide-react';

export function Dashboard() {
  const { data: metrics } = useQuery({
    queryKey: ['metrics'],
    queryFn: async () => {
      // Mock data for now
      return {
        verify_rate: 1250,
        success_rate: 99.8,
        error_count: 12,
        witness_quorum: 4,
        timeseries: []
      };
    },
    refetchInterval: 5000,
  });

  return (
    <div className="dashboard">
      <h2>System Overview</h2>
      
      <div className="metrics-grid">
        <div className="metric-card">
          <Activity className="metric-icon" />
          <div className="metric-value">{metrics?.verify_rate || 0}/s</div>
          <div className="metric-label">Verify Rate</div>
        </div>
        
        <div className="metric-card">
          <Shield className="metric-icon" />
          <div className="metric-value">{metrics?.success_rate || 0}%</div>
          <div className="metric-label">Success Rate</div>
        </div>
        
        <div className="metric-card">
          <AlertCircle className="metric-icon" />
          <div className="metric-value">{metrics?.error_count || 0}</div>
          <div className="metric-label">Errors (24h)</div>
        </div>
        
        <div className="metric-card">
          <CheckCircle className="metric-icon" />
          <div className="metric-value">{metrics?.witness_quorum || 0}/5</div>
          <div className="metric-label">Witness Quorum</div>
        </div>
      </div>
    </div>
  );
}
