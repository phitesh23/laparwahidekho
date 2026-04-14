import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// --- Private IP validation to prevent SSRF ---
function isPrivateIP(ip: string): boolean {
  // IPv4 private/reserved ranges
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts.every(p => p >= 0 && p <= 255)) {
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    if (parts[0] === 127) return true; // 127.0.0.0/8
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16
    if (parts[0] === 0) return true; // 0.0.0.0/8
    if (parts[0] >= 224) return true; // multicast + reserved
  }
  // IPv6 loopback and private
  if (ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  return false;
}

function filterPrivateIPs(ips: string[]): string[] {
  return ips.filter(ip => !isPrivateIP(ip));
}

// --- In-memory rate limiting ---
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT = 5; // max scans per window
const RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour

function checkRateLimit(clientIP: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(clientIP);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(clientIP, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}

function extractDomain(input: string): string {
  try {
    const url = new URL(input.startsWith('http') ? input : `https://${input}`);
    return url.hostname;
  } catch {
    return input.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

async function checkSubdomain(subdomain: string): Promise<{ exists: boolean; ips: string[] }> {
  try {
    const response = await fetch(
      `https://dns.google/resolve?name=${subdomain}&type=A`,
      { signal: AbortSignal.timeout(3000) }
    );
    const data = await response.json();
    if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
      return { exists: true, ips: data.Answer.map((a: any) => a.data) };
    }
    return { exists: false, ips: [] };
  } catch {
    return { exists: false, ips: [] };
  }
}

async function checkPort(hostname: string, port: number): Promise<boolean> {
  try {
    const conn = await Promise.race([
      Deno.connect({ hostname, port, transport: "tcp" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))
    ]) as Deno.TcpConn;
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function checkWebSecurity(domain: string) {
  const results: any = {
    httpAccessible: false,
    httpsAccessible: false,
    redirectsToHttps: false,
    securityHeaders: {} as Record<string, string>,
    certificate: { valid: false },
    serverInfo: '',
    technologies: [] as string[],
  };

  try {
    const httpResponse = await fetch(`http://${domain}`, {
      method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000)
    });
    results.httpAccessible = true;
    results.redirectsToHttps = httpResponse.status >= 300 && httpResponse.status < 400 &&
      (httpResponse.headers.get('location')?.startsWith('https://') || false);
  } catch { results.httpAccessible = false; }

  try {
    const httpsResponse = await fetch(`https://${domain}`, {
      method: 'HEAD', signal: AbortSignal.timeout(5000)
    });
    results.httpsAccessible = httpsResponse.ok || httpsResponse.status < 500;
    results.certificate.valid = true;
    results.serverInfo = httpsResponse.headers.get('server') || '';

    // Detect technologies from headers
    const poweredBy = httpsResponse.headers.get('x-powered-by');
    if (poweredBy) results.technologies.push(poweredBy);
    if (results.serverInfo) results.technologies.push(results.serverInfo);

    results.securityHeaders = {
      'Strict-Transport-Security': httpsResponse.headers.get('strict-transport-security') || 'Not set',
      'X-Frame-Options': httpsResponse.headers.get('x-frame-options') || 'Not set',
      'X-Content-Type-Options': httpsResponse.headers.get('x-content-type-options') || 'Not set',
      'Content-Security-Policy': httpsResponse.headers.get('content-security-policy') ? 'Present' : 'Not set',
      'X-XSS-Protection': httpsResponse.headers.get('x-xss-protection') || 'Not set',
      'Referrer-Policy': httpsResponse.headers.get('referrer-policy') || 'Not set',
      'Permissions-Policy': httpsResponse.headers.get('permissions-policy') ? 'Present' : 'Not set',
      'X-Permitted-Cross-Domain-Policies': httpsResponse.headers.get('x-permitted-cross-domain-policies') || 'Not set',
      'Cross-Origin-Opener-Policy': httpsResponse.headers.get('cross-origin-opener-policy') || 'Not set',
      'Cross-Origin-Resource-Policy': httpsResponse.headers.get('cross-origin-resource-policy') || 'Not set',
      'Cross-Origin-Embedder-Policy': httpsResponse.headers.get('cross-origin-embedder-policy') || 'Not set',
    };
  } catch {
    results.httpsAccessible = false;
    results.certificate.valid = false;
  }

  return results;
}

async function getDNSRecords(domain: string) {
  const records: Record<string, any[]> = { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: [] };
  
  for (const type of Object.keys(records)) {
    try {
      const resp = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`, { signal: AbortSignal.timeout(3000) });
      const data = await resp.json();
      if (data.Answer) {
        records[type] = data.Answer.map((a: any) => a.data);
      }
    } catch { /* skip */ }
  }
  return records;
}

async function checkHTTPMethods(domain: string): Promise<string[]> {
  const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'PATCH'];
  const allowed: string[] = [];
  
  // Try OPTIONS first
  try {
    const resp = await fetch(`https://${domain}`, { method: 'OPTIONS', signal: AbortSignal.timeout(3000) });
    const allow = resp.headers.get('allow') || resp.headers.get('access-control-allow-methods') || '';
    if (allow) return allow.split(',').map(m => m.trim());
  } catch { /* continue */ }

  for (const method of dangerousMethods) {
    try {
      const resp = await fetch(`https://${domain}`, { method, signal: AbortSignal.timeout(2000) });
      if (resp.status !== 405 && resp.status !== 501) {
        allowed.push(method);
      }
    } catch { /* skip */ }
  }
  return allowed;
}

async function checkCommonVulnPaths(domain: string): Promise<Array<{path: string, status: number, risk: string}>> {
  const paths = [
    { path: '/.env', risk: 'Critical - Environment file exposed' },
    { path: '/.git/config', risk: 'Critical - Git config exposed' },
    { path: '/wp-admin/', risk: 'High - WordPress admin panel' },
    { path: '/phpmyadmin/', risk: 'Critical - phpMyAdmin exposed' },
    { path: '/admin/', risk: 'High - Admin panel exposed' },
    { path: '/backup/', risk: 'High - Backup directory exposed' },
    { path: '/.htaccess', risk: 'Medium - htaccess file accessible' },
    { path: '/robots.txt', risk: 'Info - Robots.txt reveals paths' },
    { path: '/sitemap.xml', risk: 'Info - Sitemap found' },
    { path: '/server-status', risk: 'High - Apache server status exposed' },
    { path: '/phpinfo.php', risk: 'Critical - PHP info exposed' },
    { path: '/.well-known/security.txt', risk: 'Info - Security policy found' },
    { path: '/api/', risk: 'Medium - API endpoint exposed' },
    { path: '/wp-login.php', risk: 'High - WordPress login page' },
    { path: '/config.php', risk: 'Critical - Config file exposed' },
  ];

  const found: Array<{path: string, status: number, risk: string}> = [];
  
  for (const { path, risk } of paths) {
    try {
      const resp = await fetch(`https://${domain}${path}`, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(3000),
      });
      if (resp.status === 200 || (resp.status >= 300 && resp.status < 400)) {
        found.push({ path, status: resp.status, risk });
      }
    } catch { /* skip */ }
  }
  return found;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain: rawDomain, scanType } = await req.json();
    const domain = extractDomain(rawDomain);

    if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return new Response(
        JSON.stringify({ error: 'Valid domain is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const validScanTypes = ['quick', 'detailed', 'full'];
    const safeScanType = validScanTypes.includes(scanType) ? scanType : 'quick';

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const sendUpdate = (message: string, type = 'info') => {
          const data = JSON.stringify({ message, type, timestamp: new Date().toISOString() });
          controller.enqueue(encoder.encode(`data: ${data}\n\n`));
        };

        try {
          sendUpdate(`Initializing ${safeScanType.toUpperCase()} security scan for ${domain}...`, 'info');
          await new Promise(r => setTimeout(r, 300));

          // ── DNS Reconnaissance ──
          sendUpdate('═══ DNS Reconnaissance ═══', 'header');
          const dnsRecords = await getDNSRecords(domain);
          const allIPs: string[] = [...dnsRecords.A];

          if (dnsRecords.A.length > 0) {
            dnsRecords.A.forEach((ip: string) => sendUpdate(`A Record: ${ip}`, 'info'));
          }
          if (dnsRecords.AAAA.length > 0) {
            dnsRecords.AAAA.forEach((ip: string) => sendUpdate(`AAAA Record: ${ip}`, 'info'));
          }
          if (dnsRecords.MX.length > 0) {
            dnsRecords.MX.forEach((mx: string) => sendUpdate(`MX Record: ${mx}`, 'info'));
          }
          if (dnsRecords.NS.length > 0) {
            dnsRecords.NS.forEach((ns: string) => sendUpdate(`NS Record: ${ns}`, 'info'));
          }
          if (dnsRecords.TXT.length > 0) {
            dnsRecords.TXT.forEach((txt: string) => sendUpdate(`TXT Record: ${txt.substring(0, 80)}${txt.length > 80 ? '...' : ''}`, 'info'));
          }
          if (dnsRecords.CNAME.length > 0) {
            dnsRecords.CNAME.forEach((cn: string) => sendUpdate(`CNAME Record: ${cn}`, 'info'));
          }

          sendUpdate(`DNS reconnaissance complete. Found ${dnsRecords.A.length} A records.`, 'success');

          // ── Subdomain Enumeration ──
          sendUpdate('═══ Subdomain Enumeration (DNS Brute Force) ═══', 'header');

          const commonSubdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'webdisk', 'ns', 'server', 'host', 'support', 'dev',
            'web', 'bbs', 'ww1', 'host2', 'shop', 'forum', 'news', 'portal',
            'api', 'app', 'mobile', 'staging', 'test', 'beta', 'demo', 'blog',
            'cdn', 'cloud', 'git', 'jenkins', 'ci', 'docker', 'vpn', 'remote',
            'status', 'monitor', 'grafana', 'kibana', 'elastic', 'db', 'database',
            'backup', 'old', 'new', 'v2', 'secure', 'login', 'auth', 'sso',
            'dashboard', 'panel', 'console', 'manage', 'internal', 'intranet'
          ];

          const subdomainsToCheck = safeScanType === 'quick' ? 10 : safeScanType === 'detailed' ? 30 : commonSubdomains.length;
          const foundSubdomains: Array<{ subdomain: string; ips: string[] }> = [];

          for (const sub of commonSubdomains.slice(0, subdomainsToCheck)) {
            const fullDomain = `${sub}.${domain}`;
            sendUpdate(`Probing ${fullDomain}...`, 'scan');
            const result = await checkSubdomain(fullDomain);
            if (result.exists) {
              foundSubdomains.push({ subdomain: fullDomain, ips: result.ips });
              sendUpdate(`✓ FOUND: ${fullDomain} → ${result.ips.join(', ')}`, 'success');
            }
          }

          sendUpdate(`Subdomain enumeration complete. Found ${foundSubdomains.length} active subdomains.`, 'success');

          // ── Port Scanning ──
          sendUpdate('═══ Port Scanning (TCP Connect) ═══', 'header');

          const commonPorts = safeScanType === 'quick'
            ? [80, 443, 22, 21, 25]
            : safeScanType === 'detailed'
            ? [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443]
            : [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
               1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017, 3000, 9200, 9300, 11211];

          const portNames: Record<number, string> = {
            20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            465: 'SMTPS', 587: 'SMTP Submission', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP Proxy', 8443: 'HTTPS Alt',
            8888: 'HTTP Alt', 27017: 'MongoDB', 3000: 'Dev Server',
            9200: 'Elasticsearch', 9300: 'Elasticsearch Transport', 11211: 'Memcached'
          };

          const portCriticality: Record<number, string> = {
            23: 'CRITICAL', 3389: 'CRITICAL', 1433: 'CRITICAL', 3306: 'CRITICAL',
            5432: 'CRITICAL', 27017: 'CRITICAL', 6379: 'CRITICAL', 5900: 'CRITICAL',
            9200: 'CRITICAL', 11211: 'CRITICAL',
            21: 'HIGH', 25: 'HIGH', 110: 'HIGH', 143: 'HIGH', 8080: 'HIGH',
            22: 'MEDIUM', 53: 'MEDIUM', 587: 'MEDIUM',
            80: 'LOW', 443: 'LOW', 465: 'LOW', 993: 'LOW', 995: 'LOW', 8443: 'LOW',
          };

          const openPorts: Array<{ port: number; service: string; criticality: string }> = [];
          const targetIP = allIPs.length > 0 ? allIPs[0] : domain;
          sendUpdate(`Scanning ${commonPorts.length} ports on ${targetIP}...`, 'info');

          for (let i = 0; i < commonPorts.length; i++) {
            const port = commonPorts[i];
            const service = portNames[port] || 'Unknown';
            const isOpen = await checkPort(targetIP, port);
            if (isOpen) {
              const crit = portCriticality[port] || 'MEDIUM';
              openPorts.push({ port, service, criticality: crit });
              const icon = crit === 'CRITICAL' ? '🔴' : crit === 'HIGH' ? '🟠' : crit === 'MEDIUM' ? '🟡' : '🟢';
              sendUpdate(`${icon} Port ${port} (${service}) OPEN [${crit}]`, isOpen ? 'success' : 'info');
            }
            if ((i + 1) % 5 === 0) sendUpdate(`Progress: ${i + 1}/${commonPorts.length} ports scanned...`, 'scan');
          }

          sendUpdate(`Port scan complete. Found ${openPorts.length} open ports.`, openPorts.length > 0 ? 'success' : 'info');

          // ── Web Security Analysis ──
          let securityResults: any = null;
          let httpMethods: string[] = [];
          let vulnPaths: any[] = [];

          if (safeScanType !== 'quick') {
            sendUpdate('═══ Web Security Analysis ═══', 'header');
            securityResults = await checkWebSecurity(domain);

            if (securityResults.httpsAccessible) {
              sendUpdate('✓ HTTPS accessible, SSL/TLS certificate valid', 'success');
            } else {
              sendUpdate('✗ HTTPS not accessible or certificate invalid', 'error');
            }

            if (securityResults.httpAccessible) {
              sendUpdate(securityResults.redirectsToHttps
                ? '✓ HTTP properly redirects to HTTPS' : '⚠ HTTP does not redirect to HTTPS', securityResults.redirectsToHttps ? 'success' : 'warning');
            }

            if (securityResults.serverInfo) {
              sendUpdate(`Server: ${securityResults.serverInfo}`, 'info');
            }
            if (securityResults.technologies.length > 0) {
              sendUpdate(`Technologies detected: ${securityResults.technologies.join(', ')}`, 'info');
            }

            // Security headers
            sendUpdate('── Security Headers Check ──', 'header');
            const headers = securityResults.securityHeaders;
            const criticalHeaders = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options'];
            let missingCritical = 0;

            for (const [name, value] of Object.entries(headers)) {
              if (value === 'Not set') {
                const isCritical = criticalHeaders.includes(name);
                if (isCritical) missingCritical++;
                sendUpdate(`✗ ${name}: NOT SET${isCritical ? ' (CRITICAL)' : ''}`, isCritical ? 'error' : 'warning');
              } else {
                sendUpdate(`✓ ${name}: ${value}`, 'success');
              }
            }

            if (missingCritical > 0) {
              sendUpdate(`⚠ ${missingCritical} critical security headers missing!`, 'warning');
            }

            // HTTP Methods check
            sendUpdate('── HTTP Methods Enumeration ──', 'header');
            httpMethods = await checkHTTPMethods(domain);
            if (httpMethods.length > 0) {
              const dangerous = httpMethods.filter(m => ['PUT', 'DELETE', 'TRACE'].includes(m));
              if (dangerous.length > 0) {
                sendUpdate(`⚠ Dangerous HTTP methods enabled: ${dangerous.join(', ')}`, 'warning');
              } else {
                sendUpdate(`HTTP methods: ${httpMethods.join(', ')}`, 'info');
              }
            } else {
              sendUpdate('No additional HTTP methods detected', 'info');
            }
          }

          // ── Vulnerability Path Scanning (full only) ──
          if (safeScanType === 'full') {
            sendUpdate('═══ Sensitive Path Discovery ═══', 'header');
            vulnPaths = await checkCommonVulnPaths(domain);

            if (vulnPaths.length > 0) {
              for (const vp of vulnPaths) {
                const isCrit = vp.risk.startsWith('Critical');
                sendUpdate(`${isCrit ? '🔴' : '⚠'} ${vp.path} → ${vp.risk} (HTTP ${vp.status})`, isCrit ? 'critical' : 'warning');
              }
            } else {
              sendUpdate('✓ No sensitive paths exposed', 'success');
            }

            // Additional attack surface analysis
            sendUpdate('── Attack Surface Summary ──', 'header');
            if (foundSubdomains.length > 10) {
              sendUpdate('⚠ Large subdomain footprint - increased attack surface', 'warning');
            }
            const criticalPorts = openPorts.filter(p => p.criticality === 'CRITICAL');
            if (criticalPorts.length > 0) {
              sendUpdate(`🔴 ${criticalPorts.length} CRITICAL ports open: ${criticalPorts.map(p => `${p.port}(${p.service})`).join(', ')}`, 'critical');
            }
          }

          // ── Summary ──
          const summary = {
            domain,
            scanType: safeScanType,
            timestamp: new Date().toISOString(),
            results: {
              subdomains: foundSubdomains.map(s => s.subdomain),
              subdomainDetails: foundSubdomains,
              dnsRecords,
              networkInfo: allIPs.map(ip => ({ type: 'IPv4 Address', value: ip })),
              openPorts,
              totalSubdomains: foundSubdomains.length,
              totalIPs: allIPs.length,
              totalOpenPorts: openPorts.length,
              securityHeaders: securityResults?.securityHeaders || {},
              serverInfo: securityResults?.serverInfo || '',
              technologies: securityResults?.technologies || [],
              httpMethods,
              vulnerablePaths: vulnPaths,
              httpsAccessible: securityResults?.httpsAccessible ?? false,
              redirectsToHttps: securityResults?.redirectsToHttps ?? false,
              certificateValid: securityResults?.certificate?.valid ?? false,
            }
          };

          sendUpdate('✓ Security scan completed successfully!', 'complete');
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'summary', data: summary })}\n\n`));
          controller.close();
        } catch (error) {
          console.error('Scan execution error:', error);
          sendUpdate(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
          controller.close();
        }
      }
    });

    return new Response(stream, {
      headers: { ...corsHeaders, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' },
    });
  } catch (error) {
    console.error('Scan error:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
