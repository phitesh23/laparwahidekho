import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { scanSummary } = await req.json();

    if (!scanSummary) {
      return new Response(
        JSON.stringify({ error: 'Scan summary is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    if (!LOVABLE_API_KEY) {
      return new Response(
        JSON.stringify({ error: 'AI service not configured' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const openPortsList = scanSummary.results?.openPorts?.map((p: any) => `Port ${p.port} (${p.service})`).join(', ') || 'None';
    const subdomainsList = scanSummary.results?.subdomains?.join(', ') || 'None';

    const systemPrompt = `You are an expert cybersecurity analyst. Analyze scan results and generate a structured security report. Be specific, actionable, and professional. Use markdown formatting.`;

    const userPrompt = `Generate a comprehensive security analysis report for domain: ${scanSummary.domain}

Scan Results:
- Scan Type: ${scanSummary.scanType}
- Subdomains Found: ${subdomainsList}
- Open Ports: ${openPortsList}
- Total Subdomains: ${scanSummary.results?.totalSubdomains || 0}
- Total Open Ports: ${scanSummary.results?.totalOpenPorts || 0}

Generate a report with these sections:

1. **Executive Summary** - Brief overview of findings and overall risk level (Critical/High/Medium/Low)

2. **Open Port Analysis** - For EACH open port found:
   - Port number and service name
   - Critical Level (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low)
   - What this port is used for
   - Security risks if left open
   - Specific remediation steps to protect it

3. **Clickjacking Protection Analysis** - Based on the scan:
   - Current clickjacking vulnerability status
   - How to implement X-Frame-Options header
   - How to implement Content-Security-Policy frame-ancestors
   - Code examples for Apache, Nginx, and application-level fixes

4. **Open Port Protection Guide** - General best practices:
   - Firewall configuration recommendations
   - Which ports should be closed immediately
   - Port-specific hardening steps
   - Network segmentation advice

5. **Subdomain Security** - Analysis of discovered subdomains and attack surface

6. **Priority Action Items** - Numbered list of actions sorted by urgency

Be thorough and provide real-world actionable advice.`;

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-3-flash-preview',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        stream: true,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(
          JSON.stringify({ error: 'Rate limit exceeded. Please try again later.' }),
          { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
      if (response.status === 402) {
        return new Response(
          JSON.stringify({ error: 'AI credits exhausted. Please add funds.' }),
          { status: 402, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
      const errorText = await response.text();
      console.error('AI gateway error:', response.status, errorText);
      return new Response(
        JSON.stringify({ error: 'AI analysis failed' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    return new Response(response.body, {
      headers: { ...corsHeaders, 'Content-Type': 'text/event-stream' },
    });
  } catch (error) {
    console.error('AI report error:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
