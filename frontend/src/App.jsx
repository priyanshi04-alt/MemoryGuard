import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import './App.css'

import Dashboard from './pages/Dashboard'
import MemoryAnalysis from './pages/MemoryAnalysis'
import SecurityLogs from './pages/SecurityLogs'

function App() {
  return (
    <BrowserRouter>
      <div className="app">

        {/* Sidebar */}
        <aside className="sidebar">

          <div className="brand">
            <div className="brand-icon">M</div>

            <div>
              <h2>MemoryGuard</h2>
              <span>AI Memory Security</span>
            </div>
          </div>

          <nav>

            <Link
              className="nav-item"
              to="/"
            >
              <span>▦</span>
              Dashboard
            </Link>

            <Link
              className="nav-item"
              to="/memory-analysis"
            >
              <span>◈</span>
              Memory Analysis
            </Link>

            <Link
              className="nav-item"
              to="/security-logs"
            >
              <span>⚠</span>
              Security Logs
            </Link>

            <a
              className="nav-item"
              href="#"
              onClick={(event) => event.preventDefault()}
            >
              <span>⚙</span>
              Policy
            </a>

          </nav>

          <div className="sidebar-bottom">
            <span className="status-dot"></span>
            Gateway Online
          </div>

        </aside>

        {/* Main Content */}
        <main className="main-content">

          <Routes>

            <Route
              path="/"
              element={<Dashboard />}
            />

            <Route
              path="/memory-analysis"
              element={<MemoryAnalysis />}
            />

            <Route
              path="/security-logs"
              element={<SecurityLogs />}
            />

          </Routes>

        </main>

      </div>
    </BrowserRouter>
  )
}

export default App