import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

function Dashboard() {
  const [memories, setMemories] = useState([])
  const [stats, setStats] = useState({
    totalTrusted: 0,
    blockedAttempts: 0,
    needsReview: 0,
    riskDistribution: { low: 0, medium: 0, high: 0 }
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([
      fetch('http://localhost:8081/api/memories?status=ALL').then((response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch memories')
        }
        return response.json()
      }),
      fetch('http://localhost:8081/api/memories/stats').then((response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch statistics')
        }
        return response.json()
      })
    ])
    .then(([memoriesData, statsData]) => {
      setMemories(memoriesData)
      setStats(statsData)
    })
    .catch((err) => {
      console.error(err)
      setError('Unable to load dashboard data from backend.')
    })
    .finally(() => {
      setLoading(false)
    })
  }, [])

  /* =========================
     REAL STATISTICS
  ========================= */

  const totalMemories = stats.totalTrusted + stats.blockedAttempts + stats.needsReview

  const allowedMemories = stats.totalTrusted

  const blockedMemories = stats.blockedAttempts

  const reviewMemories = stats.needsReview

  const lowRiskMemories = stats.riskDistribution.low

  const mediumRiskMemories = stats.riskDistribution.medium

  const highRiskMemories = stats.riskDistribution.high

  const allowedPercentage =
    totalMemories > 0
      ? ((allowedMemories / totalMemories) * 100).toFixed(1)
      : '0.0'

  const highRiskPercentage =
    totalMemories > 0
      ? ((highRiskMemories / totalMemories) * 100).toFixed(1)
      : '0.0'

  const lowPercentage =
    totalMemories > 0
      ? ((lowRiskMemories / totalMemories) * 100).toFixed(1)
      : 0

  const mediumPercentage =
    totalMemories > 0
      ? ((mediumRiskMemories / totalMemories) * 100).toFixed(1)
      : 0

  const highPercentage =
    totalMemories > 0
      ? ((highRiskMemories / totalMemories) * 100).toFixed(1)
      : 0

  /* =========================
     LATEST MEMORIES
  ========================= */

  const latestMemories = [...memories]
    .sort((a, b) => {
      const dateA = a.createdAt
        ? new Date(a.createdAt).getTime()
        : 0

      const dateB = b.createdAt
        ? new Date(b.createdAt).getTime()
        : 0

      return dateB - dateA
    })
    .slice(0, 4)

  /* =========================
     HELPERS
  ========================= */

  const getRiskClass = (riskLevel) => {
    if (riskLevel === 'HIGH') {
      return 'high'
    }

    if (riskLevel === 'MEDIUM') {
      return 'medium'
    }

    return 'low'
  }

  const getDecisionClass = (status) => {
    if (status === 'BLOCKED') {
      return 'block'
    }

    if (status === 'REVIEW') {
      return 'review'
    }

    return 'allow'
  }

  const getDecisionText = (status) => {
    if (status === 'BLOCKED') {
      return 'BLOCK'
    }

    if (status === 'REVIEW') {
      return 'REVIEW'
    }

    return 'ALLOW'
  }

  const getMemoryTitle = (memory) => {
    if (memory.memoryType) {
      return memory.memoryType.replaceAll('_', ' ')
    }

    return 'Memory'
  }

  const getMemoryPreview = (content) => {
    if (!content) {
      return 'No content available'
    }

    if (content.length > 55) {
      return `${content.substring(0, 55)}...`
    }

    return content
  }

  /* =========================
     UI
  ========================= */

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">SECURITY CONSOLE</p>

          <h1>Security Overview</h1>

          <p className="subtitle">
            Monitor and analyze memories before they enter your AI agent.
          </p>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          System Healthy
        </div>
      </header>

      {/* =========================
          LOADING
      ========================= */}

      {loading && (
        <section className="panel">
          <div className="logs-state">
            Loading security overview...
          </div>
        </section>
      )}

      {/* =========================
          ERROR
      ========================= */}

      {error && (
        <section className="panel">
          <div className="logs-state error-state">
            {error}
          </div>
        </section>
      )}

      {!loading && !error && (
        <>
          {/* =========================
              STAT CARDS
          ========================= */}

          <section className="stats-grid">

            <div className="stat-card">
              <span className="stat-label">
                Total Memories
              </span>

              <strong>
                {totalMemories}
              </strong>

              <span className="stat-info">
                Analyzed by gateway
              </span>
            </div>


            <div className="stat-card">
              <span className="stat-label">
                Allowed
              </span>

              <strong className="success-text">
                {allowedMemories}
              </strong>

              <span className="stat-info">
                {allowedPercentage}% of memories
              </span>
            </div>


            <div className="stat-card">
              <span className="stat-label">
                Blocked
              </span>

              <strong className="danger-text">
                {blockedMemories}
              </strong>

              <span className="stat-info">
                Threat detected
              </span>
            </div>


            <div className="stat-card">
              <span className="stat-label">
                Needs Review
              </span>

              <strong className="warning-text">
                {reviewMemories}
              </strong>

              <span className="stat-info">
                Medium-risk memories
              </span>
            </div>

          </section>


          {/* =========================
              MEMORY ANALYSIS + RISK
          ========================= */}

          <section className="content-grid">

            {/* Memory Analysis */}

            <div className="panel">

              <div className="panel-header">

                <div>
                  <h2>
                    Memory Security Analysis
                  </h2>

                  <p>
                    Latest decisions made by the security pipeline.
                  </p>
                </div>

                <Link
                  to="/memory-analysis"
                  className="view-button"
                >
                  View All
                </Link>

              </div>


              <div className="table-wrapper">

                {latestMemories.length === 0 ? (
                  <div className="logs-state">
                    No memories analyzed yet.
                  </div>
                ) : (
                  <table>

                    <thead>
                      <tr>
                        <th>Memory</th>
                        <th>Risk</th>
                        <th>Decision</th>
                        <th>Reason</th>
                      </tr>
                    </thead>


                    <tbody>

                      {latestMemories.map((memory) => (

                        <tr key={memory.id}>

                          <td>
                            <strong>
                              {getMemoryTitle(memory)}
                            </strong>

                            <small>
                              {getMemoryPreview(memory.content)}
                            </small>
                          </td>


                          <td>
                            <span
                              className={`risk ${getRiskClass(
                                memory.riskLevel
                              )}`}
                            >
                              {memory.riskLevel || 'LOW'}
                            </span>
                          </td>


                          <td>
                            <span
                              className={`decision ${getDecisionClass(
                                memory.status
                              )}`}
                            >
                              {getDecisionText(memory.status)}
                            </span>
                          </td>


                          <td>
                            {memory.riskReason ||
                              'No major security risk detected'}
                          </td>

                        </tr>

                      ))}

                    </tbody>

                  </table>
                )}

              </div>

            </div>


            {/* Risk Distribution */}

            <div className="panel risk-panel">

              <div className="panel-header">

                <div>
                  <h2>
                    Risk Distribution
                  </h2>

                  <p>
                    Current memory risk levels.
                  </p>
                </div>

              </div>


              <div className="risk-summary">

                <div className="risk-number">

                  <strong>
                    {highRiskPercentage}%
                  </strong>

                  <span>
                    High-risk memories
                  </span>

                </div>


                <div className="risk-bars">

                  {/* LOW */}

                  <div className="bar-row">

                    <span>
                      Low
                    </span>

                    <div className="bar">

                      <div
                        className="bar-fill low-fill"
                        style={{
                          width: `${lowPercentage}%`,
                        }}
                      ></div>

                    </div>

                    <strong>
                      {lowRiskMemories}
                    </strong>

                  </div>


                  {/* MEDIUM */}

                  <div className="bar-row">

                    <span>
                      Medium
                    </span>

                    <div className="bar">

                      <div
                        className="bar-fill medium-fill"
                        style={{
                          width: `${mediumPercentage}%`,
                        }}
                      ></div>

                    </div>

                    <strong>
                      {mediumRiskMemories}
                    </strong>

                  </div>


                  {/* HIGH */}

                  <div className="bar-row">

                    <span>
                      High
                    </span>

                    <div className="bar">

                      <div
                        className="bar-fill high-fill"
                        style={{
                          width: `${highPercentage}%`,
                        }}
                      ></div>

                    </div>

                    <strong>
                      {highRiskMemories}
                    </strong>

                  </div>

                </div>

              </div>

            </div>

          </section>


          {/* =========================
              SECURITY PIPELINE
          ========================= */}

          <section className="panel pipeline-panel">

            <div className="panel-header">

              <div>
                <h2>
                  Security Pipeline
                </h2>

                <p>
                  How a memory is evaluated before storage.
                </p>
              </div>

            </div>


            <div className="pipeline">

              <div className="pipeline-step">

                <span>01</span>

                <strong>
                  Memory Gateway
                </strong>

                <small>
                  Receive memory
                </small>

              </div>


              <div className="pipeline-arrow">
                →
              </div>


              <div className="pipeline-step">

                <span>02</span>

                <strong>
                  Analysis
                </strong>

                <small>
                  Context & content
                </small>

              </div>


              <div className="pipeline-arrow">
                →
              </div>


              <div className="pipeline-step">

                <span>03</span>

                <strong>
                  Risk Engine
                </strong>

                <small>
                  Aggregate risk
                </small>

              </div>


              <div className="pipeline-arrow">
                →
              </div>


              <div className="pipeline-step">

                <span>04</span>

                <strong>
                  Policy Engine
                </strong>

                <small>
                  Allow / Block / Review
                </small>

              </div>

            </div>

          </section>
        </>
      )}
    </>
  )
}

export default Dashboard