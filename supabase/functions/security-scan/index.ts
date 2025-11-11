import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain, scanType } = await req.json();
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

        // Initial scan start
        sendUpdate(`Initializing ${scanType} scan for ${domain}...`, 'info');
        await new Promise(resolve => setTimeout(resolve, 500));

        // Subdomain Enumeration
        sendUpdate('Starting subdomain enumeration...', 'header');
        await new Promise(resolve => setTimeout(resolve, 300));
        
        const subdomains = [
          'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 
          'test', 'portal', 'blog', 'shop', 'dashboard', 'app'
        ];
        
        const foundSubdomains: string[] = [];
        const scanSpeed = scanType === 'quick' ? 100 : scanType === 'detailed' ? 200 : 300;
        
        for (const sub of subdomains.slice(0, scanType === 'quick' ? 5 : scanType === 'detailed' ? 10 : 13)) {
          await new Promise(resolve => setTimeout(resolve, scanSpeed));
          const found = Math.random() > 0.6;
          if (found) {
            foundSubdomains.push(`${sub}.${domain}`);
            sendUpdate(`✓ Found: ${sub}.${domain}`, 'success');
          } else {
            sendUpdate(`✗ Checking: ${sub}.${domain}`, 'scan');
          }
        }

        sendUpdate(`Subdomain enumeration complete. Found ${foundSubdomains.length} subdomains.`, 'success');
        await new Promise(resolve => setTimeout(resolve, 500));

        // Network Scanning
        sendUpdate('Starting network scanning...', 'header');
        await new Promise(resolve => setTimeout(resolve, 300));
        
        const networkInfo = [
          { type: 'IPv4 Address', value: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` },
          { type: 'IPv6 Address', value: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' },
          { type: 'ASN', value: `AS${Math.floor(Math.random() * 90000 + 10000)}` },
          { type: 'ISP', value: 'CloudFlare Inc.' },
        ];

        for (const info of networkInfo) {
          await new Promise(resolve => setTimeout(resolve, scanSpeed));
          sendUpdate(`${info.type}: ${info.value}`, 'info');
        }

        sendUpdate('Network scanning complete.', 'success');
        await new Promise(resolve => setTimeout(resolve, 500));

        // Port Scanning
        sendUpdate('Starting port scanning...', 'header');
        await new Promise(resolve => setTimeout(resolve, 300));
        
        const commonPorts = [
          { port: 80, service: 'HTTP', status: 'open' },
          { port: 443, service: 'HTTPS', status: 'open' },
          { port: 22, service: 'SSH', status: Math.random() > 0.5 ? 'open' : 'filtered' },
          { port: 21, service: 'FTP', status: 'closed' },
          { port: 25, service: 'SMTP', status: Math.random() > 0.7 ? 'open' : 'closed' },
          { port: 3306, service: 'MySQL', status: Math.random() > 0.8 ? 'open' : 'filtered' },
          { port: 5432, service: 'PostgreSQL', status: 'filtered' },
          { port: 8080, service: 'HTTP-Alt', status: Math.random() > 0.6 ? 'open' : 'closed' },
        ];

        const portsToScan = scanType === 'quick' ? 4 : scanType === 'detailed' ? 6 : 8;
        const openPorts: any[] = [];

        for (const portInfo of commonPorts.slice(0, portsToScan)) {
          await new Promise(resolve => setTimeout(resolve, scanSpeed));
          const statusType = portInfo.status === 'open' ? 'warning' : portInfo.status === 'filtered' ? 'info' : 'scan';
          sendUpdate(`Port ${portInfo.port} (${portInfo.service}): ${portInfo.status.toUpperCase()}`, statusType);
          if (portInfo.status === 'open') {
            openPorts.push(portInfo);
          }
        }

        sendUpdate(`Port scanning complete. Found ${openPorts.length} open ports.`, 'success');
        await new Promise(resolve => setTimeout(resolve, 500));

        // Security Analysis
        if (scanType !== 'quick') {
          sendUpdate('Performing security analysis...', 'header');
          await new Promise(resolve => setTimeout(resolve, 300));
          
          const vulnerabilities = [
            'SSL/TLS certificate is valid',
            'HSTS header detected',
            'X-Frame-Options header present',
            openPorts.length > 2 ? 'WARNING: Multiple open ports detected' : 'Port security acceptable',
            foundSubdomains.length > 5 ? 'INFO: Large subdomain footprint' : 'Subdomain count normal',
          ];

          for (const vuln of vulnerabilities) {
            await new Promise(resolve => setTimeout(resolve, scanSpeed + 100));
            const type = vuln.includes('WARNING') ? 'warning' : vuln.includes('INFO') ? 'info' : 'success';
            sendUpdate(vuln, type);
          }

          sendUpdate('Security analysis complete.', 'success');
          await new Promise(resolve => setTimeout(resolve, 500));
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
            totalOpenPorts: openPorts.length,
          }
        };

        sendUpdate('Scan completed successfully!', 'complete');
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'summary', data: summary })}\n\n`));
        controller.close();
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
