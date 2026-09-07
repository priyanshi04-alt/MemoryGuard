import { useEffect, useState } from 'react'
import API_BASE_URL from '../config/api'

function SecurityLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/security-logs`)
      .then((response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch security logs')
        }

        return response.json()
      })
      .then((data) => {
        setLogs(data)
      })
      .catch((err) => {
        console.error(err)
        setError('Unable to load security logs from backend.')
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  return (
    <div className="analysis-page">

      <div className="analysis-header">
        <p className="eyebrow">SECURITY MONITORING</p>

        <h1>Security Audit Trail</h1>

        <p className="subtitle">
          Review traceable security decisions and evidence recorded by MemoryGuard.
        </p>
      </div>

      <section className="analysis-panel">

        <div className="panel-header">
          <div>
            <h2>Audit Log Events</h2>

            <p>
              Recorded actions and policy explanations for evaluated memories.
            </p>
          </div>

          <span className="log-count">
            {logs.length} events
          </span>
        </div>

        {loading && (
          <div className="logs-state">
            Loading security logs...
          </div>
        )}

        {error && (
          <div className="logs-state error-state">
            {error}
          </div>
        )}

        {!loading && !error && logs.length === 0 && (
          <div className="logs-state">
            No security events recorded yet.
          </div>
        )}

        {!loading && !error && logs.length > 0 && (
          <div className="table-wrapper">

            <table className="security-log-table">

              <thead>
                <tr>
                  <th>ID</th>
                  <th>Memory ID</th>
                  <th>Provenance</th>
                  <th>Threat Type</th>
                  <th>Risk Score</th>
                  <th>Action</th>
                  <th>Explanation / Policy Rationale</th>
                  <th>Created At</th>
                </tr>
              </thead>

              <tbody>

                {logs.map((log) => (
                  <tr key={log.id}>

                    <td>
                      #{log.id}
                    </td>

                    <td>
                      {log.memoryId ? `Memory #${log.memoryId}` : '—'}
                    </td>

                    <td style={{fontWeight: '500'}}>
                      {log.provenance || 'UNKNOWN'}
                    </td>

                    <td>
                      <span className="threat-badge">
                        {log.threatType}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`log-risk ${
                          log.riskScore >= 80
                            ? 'high'
                            : log.riskScore >= 50
                              ? 'medium'
                              : 'low'
                        }`}
                      >
                        {log.riskScore}/100
                      </span>
                    </td>

                    <td>
                      <span
                        className={`log-action ${
                          log.actionTaken === 'BLOCKED'
                            ? 'blocked'
                            : log.actionTaken === 'REVIEW'
                              ? 'review'
                              : 'allowed'
                        }`}
                      >
                        {log.actionTaken}
                      </span>
                    </td>

                    <td style={{maxWidth: '320px', fontSize: '0.9em', color: '#cbd5e1'}}>
                      <div>{log.explanation || '—'}</div>
                      {log.contributingSignals && (
                        <div style={{fontSize: '0.8em', color: '#94a3b8', marginTop: '4px'}}>
                          <strong>Signals:</strong> {log.contributingSignals}
                        </div>
                      )}
                    </td>

                    <td className="log-date">
                      {log.createdAt
                        ? new Date(log.createdAt).toLocaleString()
                        : '—'}
                    </td>

                  </tr>
                ))}

              </tbody>

            </table>

          </div>
        )}

      </section>

    </div>
  )
}

export default SecurityLogs