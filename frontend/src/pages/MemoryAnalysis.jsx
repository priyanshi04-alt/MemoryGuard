import { useState } from 'react'

function MemoryAnalysis() {
  const [memory, setMemory] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!memory.trim()) {
      return
    }

    setLoading(true)
    setResult(null)
    setError('')

    const memoryData = {
      agentId: 1,
      content: memory,
      memoryType: 'USER_MEMORY',
      status: 'SAFE',
    }

    try {
      const response = await fetch('http://localhost:8081/api/memories', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(memoryData),
      })

      if (!response.ok) {
        throw new Error('Failed to analyze memory')
      }

      const data = await response.json()

      setResult(data)
    } catch (err) {
      console.error(err)
      setError(
        'Unable to connect to MemoryGuard backend. Make sure Spring Boot is running.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="analysis-page">
      <div className="analysis-header">
        <p className="eyebrow">MEMORY SECURITY</p>

        <h1>Memory Analysis</h1>

        <p className="subtitle">
          Analyze a memory before allowing it to enter the AI agent.
        </p>
      </div>

      {/* Submit Memory */}

      <section className="analysis-panel">
        <div className="panel-header">
          <div>
            <h2>Submit Memory</h2>

            <p>
              Enter the memory content that you want MemoryGuard to evaluate.
            </p>
          </div>
        </div>

        <div className="analysis-form">
          <label htmlFor="memory">
            Memory Content
          </label>

          <textarea
            id="memory"
            value={memory}
            onChange={(event) => setMemory(event.target.value)}
            placeholder="Example: User prefers dark mode..."
            rows="8"
            disabled={loading}
          />

          <div className="form-footer">
            <span>
              {memory.length} characters
            </span>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={!memory.trim() || loading}
            >
              {loading ? 'Analyzing...' : 'Analyze Memory'}
            </button>
          </div>
        </div>
      </section>

      {/* Error */}

      {error && (
        <section className="analysis-panel error-panel">
          <div className="error-message">
            <strong>Connection Error</strong>
            <p>{error}</p>
          </div>
        </section>
      )}

      {/* Result */}

      {result && (
        <section className="analysis-panel result-panel">
          <div className="panel-header">
            <div>
              <h2>Analysis Result</h2>

              <p>
                Security analysis performed by the MemoryGuard backend.
              </p>
            </div>

            <span
              className={`decision ${
                result.status === 'BLOCKED'
                  ? 'block'
                  : 'allow'
              }`}
            >
              {result.status}
            </span>
          </div>

          <div className="result-content">
            <div className="result-grid">

              {/* Risk Score */}

              <div className="result-card">
                <span>Risk Score</span>

                <strong
                  className={
                    result.riskScore >= 80
                      ? 'danger-text'
                      : result.riskScore >= 50
                        ? 'warning-text'
                        : 'success-text'
                  }
                >
                  {result.riskScore}/100
                </strong>
              </div>

              {/* Risk Level */}

              <div className="result-card">
                <span>Risk Level</span>

                <strong>
                  {result.riskLevel || 'UNKNOWN'}
                </strong>
              </div>

              {/* Category */}

              <div className="result-card">
                <span>Threat Category</span>

                <strong>
                  {result.riskCategory || 'NONE'}
                </strong>
              </div>
            </div>

            {/* Reason */}

            <div className="reason-box">
              <span>Analysis Reason</span>

              <p>
                {result.riskReason ||
                  'No additional reason provided by the analyzer.'}
              </p>
            </div>

            {/* Memory Information */}

            <div className="memory-info">
              <div>
                <span>Memory ID</span>
                <strong>{result.id}</strong>
              </div>

              <div>
                <span>Agent ID</span>
                <strong>{result.agentId}</strong>
              </div>

              <div>
                <span>Memory Type</span>
                <strong>{result.memoryType}</strong>
              </div>

              <div>
                <span>Integrity Hash</span>
                <strong className="hash">
                  {result.integrityHash}
                </strong>
              </div>

              {result.correlationId && (
                <div>
                  <span>Correlation ID</span>
                  <strong>{result.correlationId}</strong>
                </div>
              )}
            </div>
          </div>
        </section>
      )}
    </div>
  )
}

export default MemoryAnalysis