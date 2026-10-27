// UI fixtures. Replace this collection with scan-history responses when persistence is ready.
const examples = [
  ['cnn.com', 'F', 6, 14, false, 'TLS 1.3'],
  ['nytimes.com', 'F', 18, 9, false, 'TLS 1.2'],
  ['legacy.example', 'E', 32, 7, false, 'TLS 1.2'],
  ['shop.example', 'D', 48, 6, false, 'TLS 1.2'],
  ['news.example', 'C', 67, 4, true, 'TLS 1.3'],
  ['google.com', 'B', 82, 3, true, 'TLS 1.3'],
  ['signal.org', 'A', 97, 0, true, 'TLS 1.3'],
]

export const mockScans = examples.map(([domain, grade, score, count, csp, protocol], index) => ({
  id: `mock-${index}`,
  scannedAt: Date.parse('2026-10-27T17:00:00Z') - index * 8 * 60000,
  url: `https://${domain}`,
  final_url: `https://${domain}/`,
  grade,
  score,
  first_party_domains: [domain],
  trackers: Array.from({ length: count }, (_, i) => ({
    domain: `tracker-${i + 1}.example`,
    entity: ['Google Analytics', 'Meta Pixel', 'Microsoft Clarity', 'LinkedIn'][i % 4],
    categories: [['Analytics'], ['Advertising'], ['Session Replay'], ['Advertising']][i % 4],
  })),
  cookies: count ? [{ name: '_example', domain, httpOnly: false, secure: true, sameSite: 'None' }] : [],
  main_document: { security_headers: {
    ...(csp ? { 'content-security-policy': "default-src 'self'" } : {}),
    'strict-transport-security': 'max-age=31536000',
    'permissions-policy': 'camera=()',
  } },
  tls_info: { [domain]: { protocol, issuer: 'Example certificate authority', validTo: 1805068800 } },
}))
