import { useState, useEffect } from 'react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import './App.css'

import Dashboard from './pages/Dashboard'
import MemoryAnalysis from './pages/MemoryAnalysis'
import SecurityLogs from './pages/SecurityLogs'
import PolicyGovernance from './pages/PolicyGovernance'

function NavigationItems({ onItemClick }) {
  const location = useLocation()

  return (
    <nav className="nav-menu">
      <Link
        className={`nav-item ${location.pathname === '/' ? 'active' : ''}`}
        to="/"
        onClick={onItemClick}
      >
        <span className="nav-icon">▦</span>
        Dashboard
      </Link>

      <Link
        className={`nav-item ${location.pathname === '/memory-analysis' ? 'active' : ''}`}
        to="/memory-analysis"
        onClick={onItemClick}
      >
        <span className="nav-icon">◈</span>
        Memory Analysis
      </Link>

      <Link
        className={`nav-item ${location.pathname === '/security-logs' ? 'active' : ''}`}
        to="/security-logs"
        onClick={onItemClick}
      >
        <span className="nav-icon">⚠</span>
        Security Logs
      </Link>

      <Link
        className={`nav-item ${location.pathname === '/policy-governance' || location.pathname === '/policy' ? 'active' : ''}`}
        to="/policy-governance"
        onClick={onItemClick}
      >
        <span className="nav-icon">⚙</span>
        Policy
      </Link>
    </nav>
  )
}

function MainLayout() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('memoryguard-theme') || 'dark'
    } catch {
      return 'dark'
    }
  })
  const location = useLocation()

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark'
    setTheme(nextTheme)
    try {
      localStorage.setItem('memoryguard-theme', nextTheme)
    } catch {
      // localStorage unavailable or restricted
    }
  }

  // Sync data-theme attribute on document root
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  // Close mobile drawer on route change
  useEffect(() => {
    setMobileMenuOpen(false)
  }, [location.pathname])

  // Lock body scroll when mobile menu is open
  useEffect(() => {
    if (mobileMenuOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [mobileMenuOpen])

  return (
    <div className={`app ${theme === 'light' ? 'light-mode' : ''}`} data-theme={theme}>
      {/* Mobile Sticky Header */}
      <header className="mobile-header">
        <div className="brand">
          <div className="brand-icon">M</div>
          <div>
            <h2>MemoryGuard</h2>
            <span>AI Memory Security</span>
          </div>
        </div>

        <div className="mobile-header-actions">
          <button
            className="theme-toggle-btn mobile-theme-btn"
            onClick={toggleTheme}
            aria-label="Toggle light or dark mode"
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? '☀' : '🌙'}
          </button>
          <button
            className="mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </header>

      {/* Backdrop overlay for mobile drawer */}
      {mobileMenuOpen && (
        <div
          className="mobile-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar (Desktop) / Slide-out Drawer (Mobile) */}
      <aside className={`sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="brand desktop-brand">
          <div className="brand-icon">M</div>
          <div>
            <h2>MemoryGuard</h2>
            <span>AI Memory Security</span>
          </div>
        </div>

        <NavigationItems onItemClick={() => setMobileMenuOpen(false)} />

        <div className="sidebar-bottom">
          <span className="status-dot"></span>
          Gateway Online
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Floating Top-Right Theme Toggle Symbol */}
        <button
          className="top-theme-toggle"
          onClick={toggleTheme}
          aria-label="Toggle light or dark mode"
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? '☀' : '🌙'}
        </button>

        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/memory-analysis" element={<MemoryAnalysis />} />
          <Route path="/security-logs" element={<SecurityLogs />} />
          <Route path="/policy-governance" element={<PolicyGovernance />} />
          <Route path="/policy" element={<PolicyGovernance />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <MainLayout />
    </BrowserRouter>
  )
}

export default App