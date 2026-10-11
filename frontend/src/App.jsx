import { useState } from 'react'
import './App.css'

const HEADER_LABELS = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-frame-options': 'X-Frame-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
}

function gradeClass(grade) {
  if (grade === 'A' || grade === 'B') return 'good'
  if (grade === 'C') return 'warn'
  return 'bad'
}

function scoreClass(score) {
  if (score >= 75) return 'good'
  if (score >= 60) return 'warn'
  return 'bad'
}

function getHeaderStatus(mainDocument) {
  const present = mainDocument?.security_headers || {}
  return Object.keys(HEADER_LABELS).map((key) => ({
    key,
    label: HEADER_LABELS[key],
    present: key in present,
  }))
}

function getCookieAnalysis(cookies, firstPartyDomains) {
  const firstPartySet = new Set(firstPartyDomains)
  const firstPartyCookies = cookies.filter((c) =>
    firstPartySet.has(c.domain.replace(/^\./, ''))
  )

  return firstPartyCookies.map((c) => {
    const missing = []
    if (!c.httpOnly) missing.push('HttpOnly')
    if (!c.secure) missing.push('Secure')
    if (c.sameSite === 'None') missing.push('SameSite')
    return { name: c.name, missing }
  })
}

const AD_CATEGORIES = ['Advertising', 'Ad Motivated Tracking', 'Ad Fraud']
const ANALYTICS_CATEGORIES = ['Analytics', 'Audience Measurement', 'Third-Party Analytics Marketing']
const REPLAY_CATEGORIES = ['Session Replay']

function groupTrackers(trackers) {
  const has = (t, list) => (t.categories || []).some((c) => list.includes(c))
  return {
    advertising: trackers.filter((t) => has(t, AD_CATEGORIES)),
    analytics: trackers.filter((t) => has(t, ANALYTICS_CATEGORIES) && !has(t, AD_CATEGORIES)),
    sessionReplay: trackers.filter((t) => has(t, REPLAY_CATEGORIES)),
  }
}

function getTlsInfo(tlsInfo, finalUrl) {
  if (!finalUrl) return null
  try {
    const hostname = new URL(finalUrl).hostname
    return tlsInfo[hostname] || null
  } catch {
    return null
  }
}

function tlsStatus(protocol) {
  if (protocol === 'TLS 1.3' || protocol === 'QUIC') return 'good'
  if (protocol === 'TLS 1.2') return 'warn'
  return 'bad'
}

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

  const headers = result ? getHeaderStatus(result.main_document) : []
  const missingHeaders = headers.filter((h) => !h.present)
  const presentHeaders = headers.filter((h) => h.present)

  const cookieAnalysis = result ? getCookieAnalysis(result.cookies, result.first_party_domains) : []
  const problemCookies = cookieAnalysis.filter((c) => c.missing.length > 0)
  const goodCookies = cookieAnalysis.filter((c) => c.missing.length === 0)

  const trackerGroups = result ? groupTrackers(result.trackers) : null
  const tls = result ? getTlsInfo(result.tls_info, result.final_url) : null

  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand">
          <div className="brand-mark">◉</div>
          <span>PrivacyLens</span>
        </div>
        <small>Simple website privacy report</small>
      </div>

      <form className="scan" onSubmit={handleSubmit}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          aria-label="Website URL"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Scanning...' : 'Scan website'}
        </button>
      </form>

      <section className="history">
        <div className="history-head">
          <h2>Recent scan history</h2>
          <button type="button" disabled>View all scans</button>
        </div>
        <div className="history-list">
          <p className="metric-note">Scan history will appear here once persistence is added.</p>
        </div>
      </section>

      {error && <p className="error">Error: {error}</p>}

      {result && (
        <>
          <section className="summary">
            <div className="summary-top">
              <div className={`grade ${gradeClass(result.grade)}`}>{result.grade}</div>
              <div>
                <h1>
                  {result.grade === 'A' || result.grade === 'B'
                    ? 'This website looks reasonably privacy-respecting'
                    : 'This website has notable privacy issues'}
                </h1>
                <p>Results for {result.final_url || result.url}</p>
                <div className="scoreline">
                  <span className={`pill ${scoreClass(result.score)}`}>
                    Privacy score: {result.score} / 100
                  </span>
                  <span className={`pill ${scoreClass(result.score)}`}>
                    Overall risk: {result.score >= 75 ? 'Low' : result.score >= 60 ? 'Moderate' : 'High'}
                  </span>
                </div>
              </div>
            </div>

            <div className="plain">
              <strong>What this means in plain English</strong>
              <ul>
                {result.trackers.length > 0 && (
                  <li>Other companies can track visitors while they use this website ({result.trackers.length} found).</li>
                )}
                {problemCookies.length > 0 && (
                  <li>{problemCookies.length} cookie(s) are missing protections that help keep them secure.</li>
                )}
                {missingHeaders.length > 0 && (
                  <li>The website is missing {missingHeaders.length} browser security protection(s).</li>
                )}
                {tls && (
                  <li>
                    The connection {tlsStatus(tls.protocol) === 'good' ? 'is secure and uses modern' : 'uses'}{' '}
                    {tls.protocol}.
                  </li>
                )}
              </ul>
            </div>
          </section>

          <section className="overview">
            <div className="mini">
              <div className="number">{result.trackers.length}</div>
              <strong>Outside trackers</strong>
              <p>Services from other companies that can collect visitor activity.</p>
            </div>
            <div className="mini">
              <div className="number">{problemCookies.length}</div>
              <strong>Cookie problems</strong>
              <p>Some cookies are missing important security settings.</p>
            </div>
            <div className="mini">
              <div className="number">{missingHeaders.length}</div>
              <strong>Missing protections</strong>
              <p>Browser security headers that are not enabled.</p>
            </div>
          </section>

          <section className="section">
            <div className="section-head">
              <h2>1. Tracking</h2>
              <p>These companies may receive information when someone visits this site.</p>
            </div>

            {trackerGroups.advertising.length > 0 && (
              <div className="issue">
                <div className="icon bad">!</div>
                <div>
                  <h3>Advertising trackers are present</h3>
                  <p>{trackerGroups.advertising.map((t) => t.entity || t.domain).join(', ')} may be used to measure ads or build advertising profiles.</p>
                </div>
                <span className="status bad">High concern</span>
              </div>
            )}

            {trackerGroups.analytics.length > 0 && (
              <div className="issue">
                <div className="icon warn">!</div>
                <div>
                  <h3>Analytics tools are present</h3>
                  <p>{trackerGroups.analytics.map((t) => t.entity || t.domain).join(', ')} can measure how people use the website.</p>
                </div>
                <span className="status warn">Moderate concern</span>
              </div>
            )}

            {trackerGroups.sessionReplay.length > 0 && (
              <div className="issue">
                <div className="icon warn">!</div>
                <div>
                  <h3>Session replay is present</h3>
                  <p>{trackerGroups.sessionReplay.map((t) => t.entity || t.domain).join(', ')} can record how visitors interact with pages.</p>
                </div>
                <span className="status warn">Moderate concern</span>
              </div>
            )}

            {result.trackers.length === 0 && (
              <div className="issue">
                <div className="icon good">✓</div>
                <div>
                  <h3>No third-party trackers found</h3>
                  <p>This site did not load any known tracking services during the scan.</p>
                </div>
                <span className="status good">Good</span>
              </div>
            )}

            <details>
              <summary>Show technical tracker details</summary>
              <div className="technical">
                {result.trackers.map((t) => (
                  <div className="tech-row" key={t.domain}>
                    <span>{t.entity || 'Unknown'}</span>
                    <span>{t.domain}</span>
                  </div>
                ))}
              </div>
            </details>
          </section>

          <section className="section">
            <div className="section-head">
              <h2>2. Cookie security</h2>
              <p>Cookies are small pieces of data saved in the browser. Some are missing protections.</p>
            </div>

            {problemCookies.length > 0 && (
              <div className="issue">
                <div className="icon bad">!</div>
                <div>
                  <h3>{problemCookies.length} cookie(s) need better protection</h3>
                  <p>Some cookies are missing settings such as HttpOnly, Secure, or SameSite.</p>
                </div>
                <span className="status bad">Needs attention</span>
              </div>
            )}

            {goodCookies.length > 0 && (
              <div className="issue">
                <div className="icon good">✓</div>
                <div>
                  <h3>{goodCookies.length} cookie(s) configured well</h3>
                  <p>These cookies use the protections we expect to see.</p>
                </div>
                <span className="status good">Good</span>
              </div>
            )}

            <details>
              <summary>Show technical cookie details</summary>
              <div className="technical">
                {cookieAnalysis.map((c, i) => (
                  <div className="tech-row" key={`${c.name}-${i}`}>
                    <span>{c.name}</span>
                    <span>{c.missing.length ? `Missing ${c.missing.join(', ')}` : 'Protected'}</span>
                  </div>
                ))}
              </div>
            </details>
          </section>

          <section className="section">
            <div className="section-head">
              <h2>3. Browser security protections</h2>
              <p>These settings tell the browser how to safely handle the website.</p>
            </div>

            {missingHeaders.some((h) => h.key === 'content-security-policy') && (
              <div className="issue">
                <div className="icon bad">!</div>
                <div>
                  <h3>Content Security Policy is missing</h3>
                  <p>This is one of the most important protections against malicious scripts running in the browser.</p>
                </div>
                <span className="status bad">Important</span>
              </div>
            )}

            {missingHeaders.filter((h) => h.key !== 'content-security-policy').length > 0 && (
              <div className="issue">
                <div className="icon warn">!</div>
                <div>
                  <h3>Some anti-tracking and anti-clickjacking headers are missing</h3>
                  <p>
                    {missingHeaders
                      .filter((h) => h.key !== 'content-security-policy')
                      .map((h) => h.label)
                      .join(', ')}{' '}
                    are not fully configured.
                  </p>
                </div>
                <span className="status warn">Review</span>
              </div>
            )}

            {presentHeaders.length > 0 && (
              <div className="issue">
                <div className="icon good">✓</div>
                <div>
                  <h3>Some protections are enabled</h3>
                  <p>{presentHeaders.map((h) => h.label).join(', ')} {presentHeaders.length === 1 ? 'is' : 'are'} present.</p>
                </div>
                <span className="status good">Good</span>
              </div>
            )}

            <details>
              <summary>Show technical header details</summary>
              <div className="technical">
                {headers.map((h) => (
                  <div className="tech-row" key={h.key}>
                    <span>{h.label}</span>
                    <span>{h.present ? 'Present' : 'Missing'}</span>
                  </div>
                ))}
              </div>
            </details>
          </section>

          <section className="section">
            <div className="section-head">
              <h2>4. Connection security</h2>
              <p>This checks whether information is encrypted while traveling between the browser and the website.</p>
            </div>

            {tls ? (
              <div className="issue">
                <div className={`icon ${tlsStatus(tls.protocol)}`}>{tlsStatus(tls.protocol) === 'good' ? '✓' : '!'}</div>
                <div>
                  <h3>{tlsStatus(tls.protocol) === 'good' ? 'The connection is secure' : 'The connection could be more secure'}</h3>
                  <p>The site uses {tls.protocol}.</p>
                </div>
                <span className={`status ${tlsStatus(tls.protocol)}`}>
                  {tlsStatus(tls.protocol) === 'good' ? 'Good' : 'Review'}
                </span>
              </div>
            ) : (
              <div className="issue">
                <div className="icon warn">?</div>
                <div>
                  <h3>No TLS information available</h3>
                  <p>Could not determine the connection security for the main page.</p>
                </div>
                <span className="status warn">Unknown</span>
              </div>
            )}

            {tls && (
              <details>
                <summary>Show certificate details</summary>
                <div className="technical">
                  <div className="tech-row"><span>Protocol</span><span>{tls.protocol}</span></div>
                  <div className="tech-row"><span>Issuer</span><span>{tls.issuer}</span></div>
                  <div className="tech-row">
                    <span>Valid until</span>
                    <span>{new Date(tls.validTo * 1000).toLocaleDateString()}</span>
                  </div>
                </div>
              </details>
            )}
          </section>

          <div className="help">
            <h2>How to read this report</h2>
            <p>
              <strong>Red</strong> means something deserves attention, <strong>yellow</strong> means it is worth
              reviewing, and <strong>green</strong> means the website is doing that part well.
            </p>
          </div>

          <button type="button" onClick={() => setShowDebug(!showDebug)} className="debug-toggle">
            {showDebug ? 'Hide raw JSON' : 'Show raw JSON'}
          </button>
          {showDebug && <pre id="debug-json">{JSON.stringify(result, null, 2)}</pre>}
        </>
      )}
    </div>
  )
}

export default App
