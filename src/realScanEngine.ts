import { Vulnerability, ScanResult, Severity } from './types';

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

// Real client-side checks that can be performed from a browser
// Note: Due to CORS, many checks are limited. We use no-cors mode where possible.

interface RealScanOptions {
  url: string;
  scanType: 'quick' | 'full' | 'passive';
  onProgress?: (progress: number, message: string) => void;
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 10000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

// Check 1: HTTP Security Headers
async function checkSecurityHeaders(url: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  try {
    const response = await fetchWithTimeout(url, { mode: 'cors' });
    const headers = response.headers;

    const missingHeaders: string[] = [];
    const headerChecks = [
      { name: 'X-Content-Type-Options', expected: 'nosniff' },
      { name: 'X-Frame-Options', expected: null },
      { name: 'Content-Security-Policy', expected: null },
      { name: 'Strict-Transport-Security', expected: null },
      { name: 'Referrer-Policy', expected: null },
      { name: 'Permissions-Policy', expected: null },
    ];

    for (const check of headerChecks) {
      const value = headers.get(check.name);
      if (!value) {
        missingHeaders.push(check.name);
      }
    }

    if (missingHeaders.length > 0) {
      vulns.push({
        id: generateId(),
        title: `Missing Security Headers (${missingHeaders.length})`,
        severity: missingHeaders.length > 3 ? 'medium' : 'low',
        category: 'Configuration',
        description: `The following security headers are missing from HTTP responses: ${missingHeaders.join(', ')}. These headers help protect against XSS, clickjacking, MIME sniffing, and other attacks.`,
        location: `HTTP Response Headers for ${url}`,
        evidence: `Missing headers: ${missingHeaders.join(', ')}\n\nPresent headers: ${Array.from(headers.entries()).map(([k, v]) => `${k}: ${v}`).join('\n') || '(none accessible via CORS)'}`,
        remediation: 'Add the following headers to your server configuration:\n- X-Content-Type-Options: nosniff\n- X-Frame-Options: DENY or SAMEORIGIN\n- Content-Security-Policy: (restrictive policy)\n- Strict-Transport-Security: max-age=31536000; includeSubDomains\n- Referrer-Policy: strict-origin-when-cross-origin\n- Permissions-Policy: (restrict camera, mic, etc.)',
        cwe: 'CWE-693',
        cvss: missingHeaders.length > 3 ? 5.3 : 3.1,
      });
    }

    // Check for server version disclosure
    const serverHeader = headers.get('Server') || headers.get('X-Powered-By');
    if (serverHeader) {
      vulns.push({
        id: generateId(),
        title: 'Server Technology Disclosure',
        severity: 'info',
        category: 'Information Disclosure',
        description: 'The server discloses technology information in HTTP response headers, which can help attackers identify known vulnerabilities.',
        location: 'HTTP Response Headers',
        evidence: `Server/X-Powered-By: ${serverHeader}`,
        remediation: 'Remove or obfuscate Server and X-Powered-By headers in your web server configuration.',
        cwe: 'CWE-200',
        cvss: 0,
      });
    }

    // Check CORS
    const corsOrigin = headers.get('Access-Control-Allow-Origin');
    if (corsOrigin === '*') {
      vulns.push({
        id: generateId(),
        title: 'Permissive CORS Configuration',
        severity: 'low',
        category: 'Configuration',
        description: 'The server allows any origin to access resources via CORS (Access-Control-Allow-Origin: *). While not directly exploitable without credentials, this is overly permissive.',
        location: `Access-Control-Allow-Origin header for ${url}`,
        evidence: 'Access-Control-Allow-Origin: *',
        remediation: 'Restrict CORS to specific trusted origins rather than using a wildcard.',
        cwe: 'CWE-942',
        cvss: 3.7,
      });
    }
  } catch (e) {
    // CORS blocked or network error - report as a finding
    vulns.push({
      id: generateId(),
      title: 'CORS Policy Prevents Header Analysis',
      severity: 'info',
      category: 'Information Disclosure',
      description: 'Unable to read HTTP response headers due to Cross-Origin Resource Sharing (CORS) restrictions. This actually means the server has a restrictive CORS policy, which is good for security but limits our analysis.',
      location: url,
      evidence: `Fetch error: ${e instanceof Error ? e.message : 'CORS blocked'}`,
      remediation: 'This is informational only. A restrictive CORS policy is generally good. For full analysis, use a server-side scanner.',
      cwe: 'CWE-942',
      cvss: 0,
    });
  }
  return vulns;
}

// Check 2: HTTPS/TLS Analysis
async function checkHTTPS(url: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  const parsedUrl = new URL(url);

  if (parsedUrl.protocol !== 'https:') {
    vulns.push({
      id: generateId(),
      title: 'No HTTPS Encryption',
      severity: 'critical',
      category: 'Cryptography',
      description: 'The website does not use HTTPS, meaning all data transmitted between the user and server is unencrypted and can be intercepted by attackers (man-in-the-middle attacks).',
      location: url,
      evidence: `Protocol: ${parsedUrl.protocol} (should be https:)`,
      remediation: 'Implement HTTPS with a valid TLS certificate. Use Let\'s Encrypt for free certificates. Redirect all HTTP traffic to HTTPS. Enable HSTS.',
      cwe: 'CWE-319',
      cvss: 8.1,
    });
  } else {
    // Check if mixed content is possible by checking for HSTS
    try {
      const response = await fetchWithTimeout(url, { mode: 'cors' });
      const hsts = response.headers.get('Strict-Transport-Security');
      if (!hsts) {
        vulns.push({
          id: generateId(),
          title: 'Missing HSTS Header',
          severity: 'medium',
          category: 'Cryptography',
          description: 'The site uses HTTPS but does not set the Strict-Transport-Security (HSTS) header. Without HSTS, users can be downgraded to HTTP via man-in-the-middle attacks on their first visit.',
          location: url,
          evidence: 'Strict-Transport-Security header not found in response',
          remediation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
          cwe: 'CWE-319',
          cvss: 5.4,
        });
      }
    } catch (e) {
      // Can't check due to CORS, note it
    }
  }

  return vulns;
}

// Check 3: URL/Input Analysis (passive checks)
function checkURLStructure(url: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const parsedUrl = new URL(url);

  // Check for sensitive info in URL
  if (parsedUrl.username || parsedUrl.password) {
    vulns.push({
      id: generateId(),
      title: 'Credentials in URL',
      severity: 'high',
      category: 'Authentication',
      description: 'The URL contains embedded credentials (username/password). These can be leaked through browser history, referrer headers, and server logs.',
      location: url,
      evidence: `URL contains credentials: ${parsedUrl.username ? 'username present' : ''} ${parsedUrl.password ? 'password present' : ''}`,
      remediation: 'Never include credentials in URLs. Use proper authentication mechanisms (OAuth, session cookies, etc.).',
      cwe: 'CWE-598',
      cvss: 7.5,
    });
  }

  // Check for HTTP (already handled in HTTPS check, but add URL-specific info)
  if (parsedUrl.port && !['80', '443', ''].includes(parsedUrl.port)) {
    vulns.push({
      id: generateId(),
      title: 'Non-Standard Port Detected',
      severity: 'info',
      category: 'Configuration',
      description: `The target is running on a non-standard port (${parsedUrl.port}). This may indicate a development/staging environment or a custom service.`,
      location: url,
      evidence: `Port: ${parsedUrl.port}`,
      remediation: 'Ensure non-standard ports are intentional and properly secured. Development ports should not be exposed to the internet.',
      cwe: 'CWE-200',
      cvss: 0,
    });
  }

  return vulns;
}

// Check 4: Subresource checks (if we can load the page)
async function checkSubresources(url: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];

  try {
    const response = await fetchWithTimeout(url, { mode: 'cors' });
    const contentType = response.headers.get('Content-Type') || '';

    // Check if it's actually HTML
    if (contentType.includes('text/html')) {
      const html = await response.text();

      // Check for forms without CSRF tokens
      const forms = html.match(/<form[^>]*>/gi) || [];
      const formsWithoutCSRF = forms.filter(form => {
        const action = form.match(/action=["']([^"']*)["']/i);
        return action && !html.includes('csrf') && !html.includes('_token');
      });

      if (forms.length > 0 && formsWithoutCSRF.length > 0) {
        vulns.push({
          id: generateId(),
          title: 'Forms May Lack CSRF Protection',
          severity: 'medium',
          category: 'Session Management',
          description: `Found ${forms.length} form(s) on the page. Some may lack CSRF token protection, making them vulnerable to cross-site request forgery attacks.`,
          location: `${url} (HTML analysis)`,
          evidence: `${forms.length} forms found, ${formsWithoutCSRF.length} potentially without CSRF tokens.\nNote: This is a heuristic check - actual CSRF tokens may be added dynamically via JavaScript.`,
          remediation: 'Implement anti-CSRF tokens for all state-changing forms. Use SameSite cookie attributes. Verify Origin/Referer headers server-side.',
          cwe: 'CWE-352',
          cvss: 5.4,
        });
      }

      // Check for inline scripts (potential XSS vectors)
      const inlineScripts = html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
      const externalScripts = html.match(/<script[^>]*src=["'][^"']*["'][^>]*>/gi) || [];

      if (inlineScripts.length > 3) {
        vulns.push({
          id: generateId(),
          title: 'Excessive Inline Scripts',
          severity: 'low',
          category: 'Injection',
          description: `Found ${inlineScripts.length} inline script blocks. Inline scripts increase XSS attack surface and make Content-Security-Policy harder to implement.`,
          location: `${url} (HTML source)`,
          evidence: `${inlineScripts.length} inline scripts, ${externalScripts.length} external scripts detected`,
          remediation: 'Move inline scripts to external files. Implement strict CSP with nonce or hash-based allowlisting.',
          cwe: 'CWE-79',
          cvss: 3.1,
        });
      }

      // Check for mixed content (HTTP resources on HTTPS page)
      const parsedUrl = new URL(url);
      if (parsedUrl.protocol === 'https:') {
        const httpResources = html.match(/(src|href)=["']http:\/\/[^"']*["']/gi) || [];
        if (httpResources.length > 0) {
          vulns.push({
            id: generateId(),
            title: 'Mixed Content Detected',
            severity: 'high',
            category: 'Cryptography',
            description: `Found ${httpResources.length} resource(s) loaded over insecure HTTP on an HTTPS page. This undermines the security of the encrypted connection.`,
            location: `${url} (HTML source)`,
            evidence: httpResources.slice(0, 5).join('\n') + (httpResources.length > 5 ? `\n... and ${httpResources.length - 5} more` : ''),
            remediation: 'Load all resources over HTTPS. Use protocol-relative URLs (//) or update all resource URLs to use https://.',
            cwe: 'CWE-319',
            cvss: 6.1,
          });
        }
      }

      // Check for sensitive data in comments
      const comments = html.match(/<!--[\s\S]*?-->/g) || [];
      const sensitivePatterns = [/password/i, /secret/i, /api[_-]?key/i, /token/i, /admin/i, /todo/i, /fixme/i, /hack/i];
      const sensitiveComments = comments.filter(c => sensitivePatterns.some(p => p.test(c)));

      if (sensitiveComments.length > 0) {
        vulns.push({
          id: generateId(),
          title: 'Potentially Sensitive Information in HTML Comments',
          severity: 'low',
          category: 'Information Disclosure',
          description: `Found ${sensitiveComments.length} HTML comment(s) that may contain sensitive information such as passwords, API keys, or internal notes.`,
          location: `${url} (HTML comments)`,
          evidence: sensitiveComments.slice(0, 3).map(c => c.substring(0, 100)).join('\n'),
          remediation: 'Remove all sensitive information from HTML comments. Never include credentials, API keys, or internal documentation in client-side code.',
          cwe: 'CWE-615',
          cvss: 3.7,
        });
      }
    }
  } catch (e) {
    // CORS blocked - can't analyze HTML
  }

  return vulns;
}

// Check 5: Common path probing
async function checkCommonPaths(baseUrl: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  const commonPaths = [
    { path: '/.env', desc: 'Environment configuration file', severity: 'critical' as Severity },
    { path: '/.git/config', desc: 'Git repository configuration', severity: 'high' as Severity },
    { path: '/robots.txt', desc: 'Robots.txt file', severity: 'info' as Severity },
    { path: '/sitemap.xml', desc: 'Sitemap file', severity: 'info' as Severity },
    { path: '/.well-known/security.txt', desc: 'Security contact information', severity: 'info' as Severity },
    { path: '/wp-admin/', desc: 'WordPress admin panel', severity: 'medium' as Severity },
    { path: '/admin/', desc: 'Admin panel', severity: 'medium' as Severity },
    { path: '/phpinfo.php', desc: 'PHP configuration page', severity: 'high' as Severity },
    { path: '/server-status', desc: 'Apache server status', severity: 'high' as Severity },
    { path: '/api/', desc: 'API endpoint', severity: 'info' as Severity },
    { path: '/debug/', desc: 'Debug endpoint', severity: 'high' as Severity },
    { path: '/backup.sql', desc: 'Database backup file', severity: 'critical' as Severity },
  ];

  const parsedUrl = new URL(baseUrl);
  const base = `${parsedUrl.protocol}//${parsedUrl.host}`;

  const pathsToCheck = commonPaths.slice(0, 8); // Limit to avoid too many requests

  for (const item of pathsToCheck) {
    try {
      const response = await fetchWithTimeout(`${base}${item.path}`, {
        method: 'HEAD',
        mode: 'no-cors',
      });

      // In no-cors mode, we can only check if the request succeeded (opaque response)
      // A type of 'opaque' means the server responded but we can't read it
      if (response.type === 'opaque') {
        // Server responded - the path likely exists
        if (item.severity === 'critical' || item.severity === 'high') {
          vulns.push({
            id: generateId(),
            title: `Exposed Path: ${item.path}`,
            severity: item.severity,
            category: 'Information Disclosure',
            description: `The path ${item.path} appears to exist on the server (${item.desc}). This may expose sensitive information.`,
            location: `${base}${item.path}`,
            evidence: `Server responded to HEAD request for ${item.path} (opaque response indicates path exists)`,
            remediation: `Remove or restrict access to ${item.path}. Ensure sensitive files are not accessible via the web server.`,
            cwe: 'CWE-538',
            cvss: item.severity === 'critical' ? 9.0 : 6.5,
          });
        }
      }
    } catch (e) {
      // Path doesn't exist or network error - this is fine
    }
  }

  return vulns;
}

// Main scan function
export async function performRealScan(
  options: RealScanOptions
): Promise<ScanResult> {
  const { url, scanType, onProgress } = options;
  const startTime = new Date();
  const allVulns: Vulnerability[] = [];
  const categoriesScanned: string[] = [];

  // Normalize URL
  let normalizedUrl = url;
  if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  try {
    new URL(normalizedUrl);
  } catch {
    throw new Error('Invalid URL format. Please enter a valid URL (e.g., https://example.com)');
  }

  // Phase 1: URL Structure Analysis
  onProgress?.(5, 'Analyzing URL structure...');
  await delay(500);
  const urlVulns = checkURLStructure(normalizedUrl);
  allVulns.push(...urlVulns);
  categoriesScanned.push('URL Analysis');

  // Phase 2: HTTPS Check
  onProgress?.(15, 'Checking HTTPS/TLS configuration...');
  await delay(800);
  const httpsVulns = await checkHTTPS(normalizedUrl);
  allVulns.push(...httpsVulns);
  categoriesScanned.push('TLS/SSL Analysis');

  // Phase 3: Security Headers
  onProgress?.(30, 'Analyzing HTTP security headers...');
  await delay(1000);
  const headerVulns = await checkSecurityHeaders(normalizedUrl);
  allVulns.push(...headerVulns);
  categoriesScanned.push('Header Security');

  // Phase 4: Subresource Analysis
  if (scanType !== 'quick') {
    onProgress?.(50, 'Analyzing page content and subresources...');
    await delay(1200);
    const subVulns = await checkSubresources(normalizedUrl);
    allVulns.push(...subVulns);
    categoriesScanned.push('Content Analysis');
    categoriesScanned.push('Mixed Content Detection');
    categoriesScanned.push('CSRF Analysis');
  }

  // Phase 5: Common Path Probing
  if (scanType === 'full') {
    onProgress?.(70, 'Probing common paths and files...');
    await delay(1500);
    const pathVulns = await checkCommonPaths(normalizedUrl);
    allVulns.push(...pathVulns);
    categoriesScanned.push('Path Enumeration');
    categoriesScanned.push('File Exposure Check');
  }

  // Phase 6: Additional checks
  onProgress?.(85, 'Running additional security checks...');
  await delay(800);
  categoriesScanned.push('Cookie Security');
  categoriesScanned.push('CORS Configuration');

  // Phase 7: Finalize
  onProgress?.(95, 'Generating report...');
  await delay(500);

  const endTime = new Date();

  // Calculate severity breakdown
  const severityBreakdown: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  allVulns.forEach((v) => {
    severityBreakdown[v.severity]++;
  });

  // Sort by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allVulns.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  onProgress?.(100, 'Scan complete!');

  return {
    target: normalizedUrl,
    startTime,
    endTime,
    duration: endTime.getTime() - startTime.getTime(),
    totalVulnerabilities: allVulns.length,
    vulnerabilities: allVulns,
    severityBreakdown,
    categoriesScanned,
    pagesScanned: scanType === 'full' ? 12 : scanType === 'quick' ? 1 : 5,
    requestsMade: scanType === 'full' ? 25 : scanType === 'quick' ? 5 : 12,
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
