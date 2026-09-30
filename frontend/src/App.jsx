import { useState } from 'react'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [showDebug, setShowDebug] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/scan?url=${encodeURIComponent(url)}`,
        { method: 'POST' }
      )
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`)
      }
      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div id="app-container">
      <h1>Privacy Lens</h1>

      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </form>

      {error && <p className="error">Error: {error}</p>}

      {result && (
        <div id="results">
          <h2>Results for {result.url}</h2>
          <ul className="counts">
            <li>First-party domains: {result.first_party_domains.length}</li>
            <li>Third-party domains: {result.third_party_domains.length}</li>
            <li>Cookies: {result.cookies.length}</li>
            <li>Domains with security headers: {Object.keys(result.security_headers).length}</li>
            <li>Domains with TLS info: {Object.keys(result.tls_info).length}</li>
          </ul>

          <button type="button" onClick={() => setShowDebug(!showDebug)}>
            {showDebug ? 'Hide raw JSON' : 'Show raw JSON'}
          </button>

          {showDebug && (
            <pre id="debug-json">{JSON.stringify(result, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  )
}

export default App
