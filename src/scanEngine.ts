import { Vulnerability, ScanResult, Severity } from './types';

const vulnerabilityTemplates: Omit<Vulnerability, 'id'>[] = [
  {
    title: 'Reflected Cross-Site Scripting (XSS)',
    severity: 'high',
    category: 'Injection',
    description: 'User input is reflected in the response without proper encoding, allowing execution of arbitrary JavaScript in the context of the victim\'s browser session.',
    location: '/search?q=<script>alert(1)</script>',
    evidence: 'Response contains unescaped user input in HTML context: <input value="<script>alert(1)</script>">',
    remediation: 'Implement proper output encoding for all user-controlled data. Use Content-Security-Policy headers to mitigate XSS impact.',
    cwe: 'CWE-79',
    cvss: 7.5,
  },
  {
    title: 'SQL Injection in Login Form',
    severity: 'critical',
    category: 'Injection',
    description: 'The login form is vulnerable to SQL injection through the username parameter, allowing potential authentication bypass and data extraction.',
    location: '/api/auth/login',
    evidence: 'Payload: \' OR 1=1-- resulted in successful authentication bypass with admin privileges.',
    remediation: 'Use parameterized queries or prepared statements. Implement input validation and WAF rules as defense-in-depth.',
    cwe: 'CWE-89',
    cvss: 9.8,
  },
  {
    title: 'Missing CSRF Protection',
    severity: 'medium',
    category: 'Session Management',
    description: 'State-changing forms lack CSRF tokens, allowing attackers to forge requests on behalf of authenticated users.',
    location: '/api/account/settings',
    evidence: 'POST request to /api/account/settings succeeded without CSRF token when initiated from external origin.',
    remediation: 'Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute and verify Origin/Referer headers.',
    cwe: 'CWE-352',
    cvss: 5.4,
  },
  {
    title: 'Outdated TLS Configuration',
    severity: 'medium',
    category: 'Cryptography',
    description: 'Server supports TLS 1.0 and TLS 1.1 protocols which are deprecated and contain known vulnerabilities.',
    location: 'https://target.com:443',
    evidence: 'TLS 1.0 and TLS 1.1 are accepted. Weak cipher suites detected: TLS_RSA_WITH_RC4_128_SHA.',
    remediation: 'Disable TLS 1.0 and 1.1. Configure server to only accept TLS 1.2+ with strong cipher suites. Implement HSTS.',
    cwe: 'CWE-326',
    cvss: 5.9,
  },
  {
    title: 'Directory Listing Enabled',
    severity: 'low',
    category: 'Information Disclosure',
    description: 'Web server has directory listing enabled, exposing file structure and potentially sensitive files to attackers.',
    location: '/assets/',
    evidence: 'HTTP GET /assets/ returned 200 with directory listing containing: backup.sql, config.bak, .env',
    remediation: 'Disable directory listing in web server configuration. Add index files to all directories. Implement proper access controls.',
    cwe: 'CWE-548',
    cvss: 3.1,
  },
  {
    title: 'Server Version Disclosure',
    severity: 'info',
    category: 'Information Disclosure',
    description: 'Web server discloses version information in HTTP response headers, aiding attackers in identifying known vulnerabilities.',
    location: 'HTTP Response Headers',
    evidence: 'Server: Apache/2.4.41 (Ubuntu) X-Powered-By: PHP/7.4.3',
    remediation: 'Remove or obfuscate Server and X-Powered-By headers. Configure ServerTokens to "prod" in Apache.',
    cwe: 'CWE-200',
    cvss: 0,
  },
  {
    title: 'Insecure Cookie Configuration',
    severity: 'medium',
    category: 'Session Management',
    description: 'Session cookies are missing Secure and HttpOnly flags, making them vulnerable to interception and client-side access.',
    location: 'Set-Cookie: session_id=abc123; Path=/',
    evidence: 'Cookie "session_id" lacks Secure flag (transmitted over HTTP) and HttpOnly flag (accessible via JavaScript).',
    remediation: 'Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies. Implement session rotation.',
    cwe: 'CWE-614',
    cvss: 5.4,
  },
  {
    title: 'Path Traversal Vulnerability',
    severity: 'high',
    category: 'Injection',
    description: 'File download endpoint is vulnerable to path traversal, allowing access to arbitrary files on the server filesystem.',
    location: '/download?file=../../../etc/passwd',
    evidence: 'Request returned contents of /etc/passwd file when path traversal payload was used in file parameter.',
    remediation: 'Implement strict input validation. Use allowlists for permitted file paths. Chroot or jail file operations.',
    cwe: 'CWE-22',
    cvss: 7.5,
  },
  {
    title: 'Open Redirect',
    severity: 'low',
    category: 'Validation',
    description: 'Redirect endpoint accepts arbitrary URLs, which can be used in phishing attacks to appear legitimate.',
    location: '/redirect?url=https://evil.com',
    evidence: 'GET /redirect?url=https://evil.com responded with 302 redirect to https://evil.com',
    remediation: 'Validate redirect URLs against an allowlist of permitted domains. Use relative paths for internal redirects.',
    cwe: 'CWE-601',
    cvss: 4.7,
  },
  {
    title: 'Missing Security Headers',
    severity: 'low',
    category: 'Configuration',
    description: 'Several important security headers are missing from HTTP responses, reducing defense-in-depth protections.',
    location: 'HTTP Response Headers',
    evidence: 'Missing: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Permissions-Policy, Referrer-Policy',
    remediation: 'Implement all recommended security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Permissions-Policy.',
    cwe: 'CWE-693',
    cvss: 2.6,
  },
  {
    title: 'CORS Misconfiguration',
    severity: 'high',
    category: 'Configuration',
    description: 'Cross-Origin Resource Sharing is misconfigured, allowing any origin to make credentialed requests to the API.',
    location: '/api/data',
    evidence: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true detected.',
    remediation: 'Restrict CORS to specific trusted origins. Never use wildcard with credentials. Implement proper origin validation.',
    cwe: 'CWE-942',
    cvss: 7.1,
  },
  {
    title: 'JWT Token Not Validated',
    severity: 'critical',
    category: 'Authentication',
    description: 'API endpoints accept JWT tokens without proper signature verification, allowing token forgery.',
    location: '/api/user/profile',
    evidence: 'JWT with algorithm "none" and modified claims was accepted by the API, granting unauthorized access.',
    remediation: 'Always verify JWT signatures server-side. Reject tokens with algorithm "none". Use strong signing keys.',
    cwe: 'CWE-345',
    cvss: 9.1,
  },
  {
    title: 'Exposed Debug Endpoint',
    severity: 'high',
    category: 'Configuration',
    description: 'Debug/diagnostic endpoints are accessible in production, exposing sensitive system information.',
    location: '/debug/vars',
    evidence: 'GET /debug/vars returned environment variables, database connection strings, and internal system paths.',
    remediation: 'Disable all debug endpoints in production. Implement environment-based feature flags. Use authentication for diagnostic tools.',
    cwe: 'CWE-489',
    cvss: 7.5,
  },
  {
    title: 'Weak Password Policy',
    severity: 'medium',
    category: 'Authentication',
    description: 'Application accepts weak passwords without complexity requirements, making accounts vulnerable to brute-force attacks.',
    location: '/api/auth/register',
    evidence: 'Successfully registered account with password "123456" (6 characters, no complexity).',
    remediation: 'Enforce minimum password length of 12+ characters. Check against breached password databases. Implement rate limiting.',
    cwe: 'CWE-521',
    cvss: 5.3,
  },
  {
    title: 'XML External Entity (XXE) Injection',
    severity: 'critical',
    category: 'Injection',
    description: 'XML parser processes external entities, allowing file disclosure, SSRF, and potential remote code execution.',
    location: '/api/import',
    evidence: 'XXE payload with <!ENTITY xxe SYSTEM "file:///etc/passwd"> successfully extracted server file contents.',
    remediation: 'Disable DTD processing and external entities in XML parsers. Use JSON instead of XML where possible.',
    cwe: 'CWE-611',
    cvss: 9.8,
  },
];

const scanCategories = [
  'XSS Detection',
  'SQL Injection',
  'CSRF Testing',
  'Authentication',
  'Session Management',
  'SSL/TLS Analysis',
  'Header Security',
  'Information Disclosure',
  'File Inclusion',
  'API Security',
  'CORS Configuration',
  'Cookie Security',
];

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

function getRandomSubset<T>(arr: T[], min: number, max: number): T[] {
  const count = Math.floor(Math.random() * (max - min + 1)) + min;
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, count);
}

export function simulateScan(url: string, scanType: string): Promise<ScanResult> {
  return new Promise((resolve) => {
    const startTime = new Date();
    const duration = scanType === 'quick' ? 8000 : scanType === 'full' ? 15000 : 5000;

    setTimeout(() => {
      const selectedVulns = getRandomSubset(vulnerabilityTemplates, 4, 10).map((v) => ({
        ...v,
        id: generateId(),
      }));

      const severityBreakdown: Record<Severity, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      selectedVulns.forEach((v) => {
        severityBreakdown[v.severity]++;
      });

      const result: ScanResult = {
        target: url,
        startTime,
        endTime: new Date(),
        duration,
        totalVulnerabilities: selectedVulns.length,
        vulnerabilities: selectedVulns.sort((a, b) => {
          const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        }),
        severityBreakdown,
        categoriesScanned: getRandomSubset(scanCategories, 6, 12),
        pagesScanned: Math.floor(Math.random() * 50) + 10,
        requestsMade: Math.floor(Math.random() * 500) + 100,
      };

      resolve(result);
    }, duration);
  });
}
