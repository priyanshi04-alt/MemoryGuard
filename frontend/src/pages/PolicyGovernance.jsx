import { useEffect, useState } from 'react'
import API_BASE_URL from '../config/api'

export default function PolicyGovernance() {
  const [operatorId, setOperatorId] = useState('sec-admin')
  const [activePolicy, setActivePolicy] = useState(null)
  const [proposals, setProposals] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [health, setHealth] = useState(null)
  const [anomalies, setAnomalies] = useState(null)
  const [auditPackage, setAuditPackage] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionMessage, setActionMessage] = useState('')

  // Form state for creating proposal
  const [newProposal, setNewProposal] = useState({
    changeType: 'THRESHOLD_ADJUSTMENT',
    proposedBlockThreshold: 80,
    proposedReviewThreshold: 50,
    reason: '',
    evidence: ''
  })

  const fetchGovernanceData = () => {
    setLoading(true)
    setError('')
    const headers = {
      'Content-Type': 'application/json',
      'X-Operator-Id': operatorId
    }

    Promise.all([
      fetch(`${API_BASE_URL}/api/security/policy/active`, { headers })
        .then(res => res.ok ? res.json() : null),
      fetch(`${API_BASE_URL}/api/security/policy/proposals`, { headers })
        .then(res => res.ok ? res.json() : []),
      fetch(`${API_BASE_URL}/api/security/policy/metrics`, { headers })
        .then(res => res.ok ? res.json() : null),
      fetch(`${API_BASE_URL}/api/security/policy/health`, { headers })
        .then(res => res.ok ? res.json() : null),
      fetch(`${API_BASE_URL}/api/security/policy/anomalies/summary`, { headers })
        .then(res => res.ok ? res.json() : null),
      fetch(`${API_BASE_URL}/api/security/audit/latest`, { headers })
        .then(res => res.ok ? res.json() : null)
    ])
    .then(([activeData, proposalsData, metricsData, healthData, anomaliesData, auditData]) => {
      setActivePolicy(activeData)
      setProposals(proposalsData || [])
      setMetrics(metricsData)
      setHealth(healthData)
      setAnomalies(anomaliesData)
      setAuditPackage(auditData)
    })
    .catch(err => {
      console.error(err)
      setError('Failed to fetch governance data. Please ensure backend is running.')
    })
    .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchGovernanceData()
  }, [operatorId])

  const handleCreateProposal = (e) => {
    e.preventDefault()
    setActionMessage('')
    fetch(`${API_BASE_URL}/api/security/policy/proposals`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Operator-Id': operatorId
      },
      body: JSON.stringify(newProposal)
    })
    .then(async res => {
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Failed to create proposal')
      }
      return res.json()
    })
    .then(() => {
      setActionMessage('Policy Change Proposal created successfully.')
      setNewProposal({
        changeType: 'THRESHOLD_ADJUSTMENT',
        proposedBlockThreshold: 80,
        proposedReviewThreshold: 50,
        reason: '',
        evidence: ''
      })
      fetchGovernanceData()
    })
    .catch(err => {
      setActionMessage(`Error: ${err.message}`)
    })
  }

  const handleApprove = (proposalId) => {
    fetch(`${API_BASE_URL}/api/security/policy/proposals/${proposalId}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Operator-Id': operatorId
      },
      body: JSON.stringify({ reason: 'Approved by authorized operator in Governance UI' })
    })
    .then(res => res.ok ? res.json() : Promise.reject('Failed to approve'))
    .then(() => {
      setActionMessage(`Proposal ${proposalId} approved.`)
      fetchGovernanceData()
    })
    .catch(err => setActionMessage(`Error: ${err}`))
  }

  const handleReject = (proposalId) => {
    fetch(`${API_BASE_URL}/api/security/policy/proposals/${proposalId}/reject`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Operator-Id': operatorId
      },
      body: JSON.stringify({ reason: 'Rejected by operator in Governance UI' })
    })
    .then(res => res.ok ? res.json() : Promise.reject('Failed to reject'))
    .then(() => {
      setActionMessage(`Proposal ${proposalId} rejected.`)
      fetchGovernanceData()
    })
    .catch(err => setActionMessage(`Error: ${err}`))
  }

  const handleActivate = (proposalId) => {
    fetch(`${API_BASE_URL}/api/security/policy/proposals/${proposalId}/activate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Operator-Id': operatorId
      },
      body: JSON.stringify({ reason: 'Activated by authorized operator in Governance UI' })
    })
    .then(res => res.ok ? res.json() : Promise.reject('Failed to activate'))
    .then(() => {
      setActionMessage(`Proposal ${proposalId} activated into runtime policy.`)
      fetchGovernanceData()
    })
    .catch(err => setActionMessage(`Error: ${err}`))
  }

  const handleGenerateAuditPackage = () => {
    fetch(`${API_BASE_URL}/api/security/audit/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Operator-Id': operatorId
      },
      body: JSON.stringify({
        packageType: 'PERIODIC_COMPLIANCE',
        notes: 'Generated via MemoryGuard Governance Portal'
      })
    })
    .then(async res => {
      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Failed to generate package')
      }
      return res.json()
    })
    .then(data => {
      setActionMessage(`Audit package ${data.packageId} generated successfully.`)
      fetchGovernanceData()
    })
    .catch(err => setActionMessage(`Error: ${err.message}`))
  }

  return (
    <div className="analysis-page">
      <div className="analysis-header">
        <p className="eyebrow">SECURITY GOVERNANCE & COMPLIANCE</p>
        <h1>Policy Governance & Audit Readiness</h1>
        <p className="subtitle">
          Controlled Policy Versioning, Invariant Protection, and Cryptographic Evidence Packaging.
        </p>
        <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <label style={{ fontSize: '13px', color: '#94a3b8' }}>Operator Identity:</label>
          <input
            type="text"
            value={operatorId}
            onChange={(e) => setOperatorId(e.target.value)}
            className="gov-input"
            style={{ width: '180px' }}
          />
          <button
            onClick={fetchGovernanceData}
            className="gov-btn"
          >
            Refresh
          </button>
        </div>
      </div>

      {actionMessage && (
        <div style={{
          margin: '16px 0',
          padding: '12px 16px',
          background: actionMessage.startsWith('Error') ? '#7f1d1d' : '#064e3b',
          color: '#f8fafc',
          borderRadius: '8px',
          fontSize: '14px'
        }}>
          {actionMessage}
        </div>
      )}

      {loading && <div className="logs-state">Loading governance telemetry...</div>}
      {error && <div className="logs-state error-state">{error}</div>}

      {!loading && (
        <>
          {/* Top Status & Metrics Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px', marginBottom: '24px' }}>
            <div className="gov-card">
              <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', marginBottom: '6px' }}>Active Policy Version</div>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#38bdf8' }}>
                v{activePolicy?.version || 1}
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                State: <span style={{ color: '#34d399', fontWeight: '600' }}>{activePolicy?.status || 'ACTIVE'}</span>
              </div>
            </div>

            <div className="gov-card">
              <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', marginBottom: '6px' }}>Enforcement Thresholds</div>
              <div style={{ fontSize: '16px', fontWeight: '600', color: '#e2e8f0' }}>
                Block: <span style={{ color: '#f87171' }}>{activePolicy?.blockThreshold ?? 80}</span> | Review: <span style={{ color: '#fbbf24' }}>{activePolicy?.reviewThreshold ?? 50}</span>
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                Fail-Safe: {activePolicy?.failSafeDefaultDecision || 'REVIEW'}
              </div>
            </div>

            <div className="gov-card">
              <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', marginBottom: '6px' }}>Governance Health</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: health?.status === 'HEALTHY' ? '#34d399' : (health?.status === 'WARNING' ? '#fbbf24' : '#f87171') }}>
                {health?.status || 'CHECKING'}
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                Pending Proposals: {health?.pendingProposalCount || 0}
              </div>
            </div>

            <div className="gov-card">
              <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', marginBottom: '6px' }}>Audit Readiness (Day 36)</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: auditPackage?.readinessStatus === 'READY' ? '#34d399' : '#38bdf8' }}>
                {auditPackage ? auditPackage.readinessStatus : 'NOT GENERATED'}
              </div>
              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                {auditPackage ? `Pkg: ${auditPackage.packageId}` : 'Generate package below'}
              </div>
            </div>
          </div>

          {/* Audit Package Section (Day 36) */}
          <section className="analysis-panel" style={{ marginBottom: '24px' }}>
            <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2>Day 36 Security Audit Package & Compliance</h2>
                <p>Deterministic, cryptographically verifiable evidence package for auditors.</p>
              </div>
              <button
                onClick={handleGenerateAuditPackage}
                style={{
                  background: '#0284c7',
                  color: '#fff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontWeight: '600',
                  fontSize: '13px'
                }}
              >
                + Generate Audit Package
              </button>
            </div>

            {auditPackage ? (
              <div className="gov-box">
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                  <div><strong>Package ID:</strong> <span style={{ color: '#38bdf8' }}>{auditPackage.packageId}</span></div>
                  <div><strong>Status:</strong> <span style={{ color: '#34d399' }}>{auditPackage.packageStatus}</span></div>
                  <div><strong>Readiness:</strong> <span style={{ color: '#fbbf24' }}>{auditPackage.readinessStatus}</span></div>
                  <div><strong>Evidence Records:</strong> {auditPackage.totalEvidenceRecords} ({auditPackage.verifiedEvidenceRecords} verified)</div>
                  <div><strong>Snapshot ID:</strong> {auditPackage.snapshotId}</div>
                  <div><strong>Attestation ID:</strong> {auditPackage.attestationId}</div>
                </div>
                <div style={{ marginTop: '10px', fontSize: '12px', color: '#64748b', wordBreak: 'break-all' }}>
                  <strong>Package SHA-256 Hash:</strong> <code>{auditPackage.packageHash}</code>
                </div>
              </div>
            ) : (
              <div className="logs-state">No audit package generated yet. Click "Generate Audit Package" to compile authoritative evidence.</div>
            )}
          </section>

          {/* Proposals List */}
          <section className="analysis-panel" style={{ marginBottom: '24px' }}>
            <div className="panel-header">
              <div>
                <h2>Policy Change Proposals ({proposals.length})</h2>
                <p>Review and act upon proposed policy calibration requests.</p>
              </div>
            </div>

            {proposals.length === 0 ? (
              <div className="logs-state">No policy proposals submitted yet.</div>
            ) : (
              <div className="table-wrapper">
                <table className="security-log-table">
                  <thead>
                    <tr>
                      <th>Proposal ID</th>
                      <th>Change Type</th>
                      <th>Proposed Thresholds</th>
                      <th>Reason</th>
                      <th>Status</th>
                      <th>Created By</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {proposals.map(p => (
                      <tr key={p.proposalId}>
                        <td><code>{p.proposalId}</code></td>
                        <td>{p.changeType}</td>
                        <td>Block: {p.proposedBlockThreshold} | Review: {p.proposedReviewThreshold}</td>
                        <td>{p.reason}</td>
                        <td>
                          <span style={{
                            padding: '3px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: '600',
                            background: p.status === 'ACTIVE' ? '#065f46' : (p.status === 'APPROVED' ? '#1e3a8a' : (p.status === 'REJECTED' ? '#7f1d1d' : '#854d0e')),
                            color: '#fff'
                          }}>
                            {p.status}
                          </span>
                        </td>
                        <td>{p.createdBy}</td>
                        <td>
                          {p.status === 'PENDING_APPROVAL' && (
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button
                                onClick={() => handleApprove(p.proposalId)}
                                style={{ background: '#16a34a', color: '#fff', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => handleReject(p.proposalId)}
                                style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}
                              >
                                Reject
                              </button>
                            </div>
                          )}
                          {p.status === 'APPROVED' && (
                            <button
                              onClick={() => handleActivate(p.proposalId)}
                              style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px' }}
                            >
                              Activate
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Create Proposal Form */}
          <section className="analysis-panel">
            <div className="panel-header">
              <div>
                <h2>Create Policy Change Proposal</h2>
                <p>Submit a formal calibration proposal to the Policy Governance layer.</p>
              </div>
            </div>

            <form onSubmit={handleCreateProposal} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginTop: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>Change Type</label>
                <select
                  value={newProposal.changeType}
                  onChange={(e) => setNewProposal({ ...newProposal, changeType: e.target.value })}
                  className="gov-input"
                  style={{ width: '100%', padding: '8px' }}
                >
                  <option value="THRESHOLD_ADJUSTMENT">THRESHOLD_ADJUSTMENT</option>
                  <option value="RECALIBRATION">RECALIBRATION</option>
                  <option value="EMERGENCY_OVERRIDE">EMERGENCY_OVERRIDE</option>
                  <option value="CUSTOM">CUSTOM</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>Proposed Block Threshold (0-100)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={newProposal.proposedBlockThreshold}
                  onChange={(e) => setNewProposal({ ...newProposal, proposedBlockThreshold: parseInt(e.target.value) || 0 })}
                  className="gov-input"
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>Proposed Review Threshold (0-100)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={newProposal.proposedReviewThreshold}
                  onChange={(e) => setNewProposal({ ...newProposal, proposedReviewThreshold: parseInt(e.target.value) || 0 })}
                  className="gov-input"
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>

              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>Reason / Operational Rationale</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Tightening block threshold following adversarial test review"
                  value={newProposal.reason}
                  onChange={(e) => setNewProposal({ ...newProposal, reason: e.target.value })}
                  className="gov-input"
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>

              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>Evidence / Supporting Benchmark References</label>
                <input
                  type="text"
                  placeholder="e.g. Benchmark run BMK-2026-09-30 showed 0 FN with block threshold 80"
                  value={newProposal.evidence}
                  onChange={(e) => setNewProposal({ ...newProposal, evidence: e.target.value })}
                  className="gov-input"
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>

              <div style={{ gridColumn: '1 / -1' }}>
                <button
                  type="submit"
                  style={{
                    background: '#2563eb',
                    color: '#fff',
                    border: 'none',
                    padding: '10px 20px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontWeight: '600'
                  }}
                >
                  Submit Proposal
                </button>
              </div>
            </form>
          </section>
        </>
      )}
    </div>
  )
}
