import { useEffect, useRef, useState } from 'react'
import PrivacyLensLogo from './PrivacyLensLogo.jsx'
import './Landing.css'

const APP_HREF = '#/app'

// Example result shown in the "Why PrivacyLens" section.
// TODO: replace every value below with a real PrivacyLens scan of cnn.com.
const SAMPLE = {
  site: 'cnn.com',
  scannedOn: 'Nov 2026',
  score: 64,
  grade: 'C',
  trackers: 14,
  companies: 6,
  unprotectedCookies: 3,
  tls: 'TLS 1.3',
  summary: 'This site shares your visit with several advertising companies.',
}

// Same thresholds as gradeClass() in App.jsx.
function gradeTone(grade) {
  if (grade === 'A' || grade === 'B') return 'good'
  if (grade === 'C') return 'warn'
  return 'bad'
}
const RING_RADIUS = 52
const RING_LENGTH = 2 * Math.PI * RING_RADIUS
const COUNT_DURATION_MS = 1400
const REDUCED_MOTION =
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

function ScorePreview() {
  const ref = useRef(null)
  const [visible, setVisible] = useState(false)
  const [count, setCount] = useState(0)

  // Start the animation the first time the card scrolls into view.
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setVisible(true)
        observer.disconnect()
      }
    }, { threshold: 0.4 })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Count the number up with the same ease-out curve the ring uses.
  useEffect(() => {
    if (!visible || REDUCED_MOTION) return
    let frame
    const start = performance.now()
    const tick = (now) => {
      const t = Math.min((now - start) / COUNT_DURATION_MS, 1)
      setCount(Math.round((1 - Math.pow(1 - t, 3)) * SAMPLE.score))
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [visible])

  const shownScore = REDUCED_MOTION && visible ? SAMPLE.score : count
  const ringOffset = visible ? RING_LENGTH * (1 - SAMPLE.score / 100) : RING_LENGTH

  return (
    <div
      ref={ref}
      className={`lp-score tone-${gradeTone(SAMPLE.grade)}${visible ? ' is-visible' : ''}`}
      role="img"
      aria-label={`Example scan of ${SAMPLE.site}: grade ${SAMPLE.grade}, score ${SAMPLE.score} out of 100`}
    >
      <div className="lp-score-head">
        <span>Real scan · {SAMPLE.scannedOn}</span>
        <span className="lp-score-site">{SAMPLE.site}</span>
      </div>
      <div className="lp-score-main">
        <div className="lp-ring">
          <svg viewBox="0 0 120 120" aria-hidden="true">
            <circle className="lp-ring-track" cx="60" cy="60" r={RING_RADIUS} />
            <circle
              className="lp-ring-fill"
              cx="60" cy="60" r={RING_RADIUS}
              strokeDasharray={RING_LENGTH}
              style={{ strokeDashoffset: ringOffset }}
            />
          </svg>
          <div className="lp-ring-label">
            <span className="lp-ring-grade">{SAMPLE.grade}</span>
            <span className="lp-ring-score">{shownScore}/100</span>
          </div>
        </div>
        <ul className="lp-score-facts">
          <li style={{ '--i': 0 }}>
            <b className="bad">{SAMPLE.trackers}</b> trackers from {SAMPLE.companies} companies
          </li>
          <li style={{ '--i': 1 }}>
            <b className="warn">{SAMPLE.unprotectedCookies}</b> cookies without protection
          </li>
          <li style={{ '--i': 2 }}>
            <b className="good">{SAMPLE.tls}</b> secure connection
          </li>
        </ul>
      </div>
      <p className="lp-score-plain">&ldquo;{SAMPLE.summary}&rdquo;</p>
    </div>
  )
}

function scrollToId(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

export default function Landing() {
  return (
    <div className="landing">
      <header className="lp-nav">
        <div className="lp-container lp-nav-inner">
          <a className="lp-brand" href="#" aria-label="PrivacyLens home">
            <PrivacyLensLogo size={28} title="" className="lp-brand-mark" />
            PrivacyLens
          </a>
          <nav className="lp-links" aria-label="Main">
            <button type="button" onClick={() => scrollToId('goal')}>Why PrivacyLens</button>
            <button type="button" onClick={() => scrollToId('preview')}>Product</button>
          </nav>
          <a className="lp-cta lp-cta-small" href={APP_HREF}>Get started</a>
        </div>
      </header>

      <main>
        <section className="lp-hero">
          <div className="lp-container">
            <h1>
              See who's watching
              <br />
              every website you visit
            </h1>
            <div className="lp-hero-foot">
              <p>
                PrivacyLens scans any website and explains its trackers, cookies and security
                in plain language. No technical knowledge needed.
              </p>
              <div className="lp-hero-actions">
                <a className="lp-cta" href={APP_HREF}>Get started</a>
                <button type="button" className="lp-ghost" onClick={() => scrollToId('preview')}>
                  See the product <span aria-hidden="true">&rarr;</span>
                </button>
              </div>
            </div>
          </div>
        </section>

        <section className="lp-goal" id="goal">
          <div className="lp-container">
            <p className="lp-eyebrow">The goal</p>
            <div className="lp-goal-grid">
              <div>
                <h2>Privacy tools are built for engineers. PrivacyLens is built for everyone else.</h2>
                <p>
                  Most people can't read network logs or cookie headers, but they still deserve to
                  know what a website does with their data. PrivacyLens visits a site the way a real
                  browser would, finds the companies tracking you, and turns it all into a simple
                  grade and a short, readable report.
                </p>
              </div>
              <ScorePreview />
            </div>
          </div>
        </section>

        <section className="lp-preview" id="preview">
          <div className="lp-container">
            <p className="lp-eyebrow">Product</p>
            <h2>One scan. One clear answer.</h2>
            <div className="lp-frame" role="img" aria-label="Product preview coming soon">
              <div className="lp-frame-bar">
                <span /><span /><span />
                <div className="lp-frame-url">privacylens / scan</div>
              </div>
              <div className="lp-frame-body">
                <p>Product preview coming soon</p>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-container lp-footer-inner">
          <span>PrivacyLens</span>
          <a href={APP_HREF}>Open the scanner &rarr;</a>
        </div>
      </footer>
    </div>
  )
}
