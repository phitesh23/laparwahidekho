import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Helper to extract domain from URL
function extractDomain(input: string): string {
  try {
    const url = new URL(input.startsWith('http') ? input : `https://${input}`);
    return url.hostname;
  } catch {
    return input.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

// Real DNS lookup using Google DNS-over-HTTPS
async function checkSubdomain(subdomain: string): Promise<boolean> {
  try {
    const response = await fetch(
      `https://dns.google/resolve?name=${subdomain}&type=A`,
      { signal: AbortSignal.timeout(3000) }
    );
    const data = await response.json();
    return data.Status === 0 && data.Answer && data.Answer.length > 0;
  } catch {
    return false;
  }
}

// Real port scanning using TCP connections
async function checkPort(hostname: string, port: number): Promise<boolean> {
  try {
    const conn = await Promise.race([
      Deno.connect({ hostname, port, transport: "tcp" }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('timeout')), 2000)
      )
    ]) as Deno.TcpConn;
    conn.close();
    return true;
  } catch {
    return false;
  }
}

// Real SSL/TLS and security headers check
async function checkWebSecurity(domain: string) {
  const results = {
    httpAccessible: false,
    httpsAccessible: false,
    redirectsToHttps: false,
    securityHeaders: {} as Record<string, string | boolean>,
    certificate: {
      valid: false,
      issuer: '',
      expiryDays: 0
    }
  };

  try {
    // Check HTTP
    const httpResponse = await fetch(`http://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(5000)
    });
    results.httpAccessible = true;
    results.redirectsToHttps = httpResponse.status >= 300 && httpResponse.status < 400 && 
      httpResponse.headers.get('location')?.startsWith('https://') || false;
  } catch {
    results.httpAccessible = false;
  }

  try {
    // Check HTTPS and security headers
    const httpsResponse = await fetch(`https://${domain}`, {
      method: 'HEAD',
      signal: AbortSignal.timeout(5000)
    });
    results.httpsAccessible = httpsResponse.ok;
    results.certificate.valid = true;

    // Check security headers
    results.securityHeaders = {
      'Strict-Transport-Security': httpsResponse.headers.get('strict-transport-security') || 'Not set',
      'X-Frame-Options': httpsResponse.headers.get('x-frame-options') || 'Not set',
      'X-Content-Type-Options': httpsResponse.headers.get('x-content-type-options') || 'Not set',
      'Content-Security-Policy': httpsResponse.headers.get('content-security-policy') ? 'Present' : 'Not set',
      'X-XSS-Protection': httpsResponse.headers.get('x-xss-protection') || 'Not set',
      'Referrer-Policy': httpsResponse.headers.get('referrer-policy') || 'Not set',
    };
  } catch {
    results.httpsAccessible = false;
    results.certificate.valid = false;
  }

  return results;
}

// Get IP address info
async function getIPInfo(domain: string) {
  try {
    const response = await fetch(
      `https://dns.google/resolve?name=${domain}&type=A`,
      { signal: AbortSignal.timeout(3000) }
    );
    const data = await response.json();
    
    if (data.Answer && data.Answer.length > 0) {
      return data.Answer.map((record: any) => record.data);
    }
    return [];
  } catch {
    return [];
  }
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain: rawDomain, scanType } = await req.json();
    const domain = extractDomain(rawDomain);
    console.log(`Starting ${scanType} scan for domain: ${domain}`);

    if (!domain) {
      return new Response(
        JSON.stringify({ error: 'Domain is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const sendUpdate = (message: string, type: string = 'info') => {
          const data = JSON.stringify({ message, type, timestamp: new Date().toISOString() });
          controller.enqueue(encoder.encode(`data: ${data}\n\n`));
        };

        try {
          sendUpdate(`Initializing real security scan for ${domain}...`, 'info');
          await new Promise(resolve => setTimeout(resolve, 500));

          // Real Subdomain Enumeration
          sendUpdate('Starting real subdomain enumeration via DNS...', 'header');
          
          const commonSubdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'webdisk', 'ns', 'server', 'host', 'support', 'dev',
            'web', 'bbs', 'ww1', 'host2', 'shop', 'forum', 'news', 'portal',
            'api', 'app', 'mobile', 'staging', 'test', 'beta', 'demo', 'blog'
          ];

          const subdomainsToCheck = scanType === 'quick' ? 8 : scanType === 'detailed' ? 20 : 32;
          const foundSubdomains: string[] = [];

          for (const sub of commonSubdomains.slice(0, subdomainsToCheck)) {
            const fullDomain = `${sub}.${domain}`;
            sendUpdate(`Checking ${fullDomain}...`, 'scan');
            
            const exists = await checkSubdomain(fullDomain);
            
            if (exists) {
              foundSubdomains.push(fullDomain);
              sendUpdate(`✓ Found: ${fullDomain}`, 'success');
            } else {
              sendUpdate(`✗ Not found: ${fullDomain}`, 'scan');
            }
          }

          sendUpdate(`Subdomain enumeration complete. Found ${foundSubdomains.length} active subdomains.`, 'success');
          await new Promise(resolve => setTimeout(resolve, 500));

          // Real Network Information
          sendUpdate('Gathering network information...', 'header');
          
          const ipAddresses = await getIPInfo(domain);
          const networkInfo: any[] = [];
          
          if (ipAddresses.length > 0) {
            for (const ip of ipAddresses) {
              networkInfo.push({ type: 'IPv4 Address', value: ip });
              sendUpdate(`IPv4 Address: ${ip}`, 'info');
            }
          } else {
            sendUpdate('No DNS A records found', 'warning');
          }

          sendUpdate('Network scanning complete.', 'success');
          await new Promise(resolve => setTimeout(resolve, 500));

          // Real Port Scanning
          sendUpdate('Starting real port scanning...', 'header');
          
          const commonPorts = scanType === 'quick' 
            ? [80, 443, 22, 21, 25] // HTTP, HTTPS, SSH, FTP, SMTP
            : scanType === 'detailed'
            ? [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 8080, 8443] // + common services
            : [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 
               1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017, 3000]; // comprehensive

          const portNames: Record<number, string> = {
            20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP Alt', 8443: 'HTTPS Alt',
            8888: 'HTTP Alt', 27017: 'MongoDB', 3000: 'Node.js'
          };

          const openPorts: Array<{port: number, service: string}> = [];
          
          // Get first IP address for port scanning
          const targetIP = ipAddresses.length > 0 ? ipAddresses[0] : domain;
          sendUpdate(`Scanning ${commonPorts.length} ports on ${targetIP}...`, 'info');

          for (let i = 0; i < commonPorts.length; i++) {
            const port = commonPorts[i];
            const serviceName = portNames[port] || 'Unknown';
            
            const isOpen = await checkPort(targetIP, port);
            
            if (isOpen) {
              openPorts.push({ port, service: serviceName });
              sendUpdate(`✓ Port ${port} (${serviceName}) is OPEN`, 'success');
            }
            
            // Progress update every 5 ports
            if ((i + 1) % 5 === 0) {
              sendUpdate(`Scanned ${i + 1}/${commonPorts.length} ports...`, 'scan');
            }
          }

          if (openPorts.length > 0) {
            sendUpdate(`Port scanning complete. Found ${openPorts.length} open ports.`, 'success');
          } else {
            sendUpdate('Port scanning complete. No open ports found (may be filtered).', 'info');
          }
          await new Promise(resolve => setTimeout(resolve, 500));

          // Real SSL/TLS and Security Analysis
          if (scanType !== 'quick') {
            sendUpdate('Performing real security analysis...', 'header');
            
            const securityResults = await checkWebSecurity(domain);

            // HTTP/HTTPS Status
            if (securityResults.httpsAccessible) {
              sendUpdate('✓ HTTPS is accessible', 'success');
              sendUpdate('✓ SSL/TLS certificate is valid', 'success');
            } else {
              sendUpdate('✗ HTTPS is not accessible or certificate invalid', 'warning');
            }

            if (securityResults.httpAccessible) {
              if (securityResults.redirectsToHttps) {
                sendUpdate('✓ HTTP redirects to HTTPS', 'success');
              } else {
                sendUpdate('⚠ HTTP does not redirect to HTTPS', 'warning');
              }
            }

            // Security Headers Analysis
            sendUpdate('Analyzing security headers...', 'header');
            
            const headers = securityResults.securityHeaders;
            
            if (headers['Strict-Transport-Security'] !== 'Not set') {
              sendUpdate(`✓ HSTS: ${headers['Strict-Transport-Security']}`, 'success');
            } else {
              sendUpdate('✗ HSTS header missing (Strict-Transport-Security)', 'warning');
            }

            if (headers['X-Frame-Options'] !== 'Not set') {
              sendUpdate(`✓ X-Frame-Options: ${headers['X-Frame-Options']}`, 'success');
            } else {
              sendUpdate('✗ X-Frame-Options header missing (Clickjacking risk)', 'warning');
            }

            if (headers['X-Content-Type-Options'] !== 'Not set') {
              sendUpdate(`✓ X-Content-Type-Options: ${headers['X-Content-Type-Options']}`, 'success');
            } else {
              sendUpdate('✗ X-Content-Type-Options header missing', 'warning');
            }

            if (headers['Content-Security-Policy'] === 'Present') {
              sendUpdate('✓ Content-Security-Policy header present', 'success');
            } else {
              sendUpdate('✗ Content-Security-Policy header missing (XSS risk)', 'warning');
            }

            if (headers['Referrer-Policy'] !== 'Not set') {
              sendUpdate(`✓ Referrer-Policy: ${headers['Referrer-Policy']}`, 'success');
            } else {
              sendUpdate('ℹ Referrer-Policy header not set', 'info');
            }

            // Additional security checks for full scan
            if (scanType === 'full') {
              sendUpdate('Performing additional security checks...', 'header');
              
              if (foundSubdomains.length > 10) {
                sendUpdate('⚠ Large subdomain footprint detected - increased attack surface', 'warning');
              }

              if (!securityResults.certificate.valid && securityResults.httpAccessible) {
                sendUpdate('⚠ Site accessible via HTTP without valid HTTPS', 'warning');
              }
            }

            sendUpdate('Security analysis complete.', 'success');
          }

          // Generate summary
          const summary = {
            domain,
            scanType,
            timestamp: new Date().toISOString(),
            results: {
              subdomains: foundSubdomains,
              networkInfo,
              openPorts,
              totalSubdomains: foundSubdomains.length,
              totalIPs: ipAddresses.length,
              totalOpenPorts: openPorts.length,
            }
          };

          sendUpdate('✓ Real security scan completed successfully!', 'complete');
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'summary', data: summary })}\n\n`));
          controller.close();
        } catch (error) {
          console.error('Scan execution error:', error);
          sendUpdate(`Error during scan: ${error instanceof Error ? error.message : 'Unknown error'}`, 'warning');
          controller.close();
        }
      }
    });

    return new Response(stream, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    });

  } catch (error) {
    console.error('Scan error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Internal server error';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
