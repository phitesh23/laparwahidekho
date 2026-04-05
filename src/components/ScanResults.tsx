import { useEffect, useRef, useState, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Download, Terminal } from "lucide-react";
import jsPDF from "jspdf";
import AISecurityReport from "./AISecurityReport";

interface ScanMessage {
  message: string;
  type: string;
  timestamp: string;
}

interface ScanResultsProps {
  messages: ScanMessage[];
  isScanning: boolean;
  scanSummary: any;
  onReset: () => void;
}

const ScanResults = ({ messages, isScanning, scanSummary, onReset }: ScanResultsProps) => {
  const resultsRef = useRef<HTMLDivElement>(null);
  const [aiReport, setAiReport] = useState("");

  useEffect(() => {
    if (resultsRef.current) {
      resultsRef.current.scrollTop = resultsRef.current.scrollHeight;
    }
  }, [messages]);

  const handleAiReportGenerated = useCallback((reportText: string) => {
    setAiReport(reportText);
  }, []);

  const getMessageColor = (type: string) => {
    switch (type) {
      case 'success': return 'text-primary';
      case 'warning': return 'text-warning';
      case 'error': case 'critical': return 'text-critical';
      case 'header': return 'text-secondary font-bold';
      case 'scan': return 'text-muted-foreground';
      default: return 'text-terminal-text';
    }
  };

  const generatePDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 20;
    const maxWidth = pageWidth - 2 * margin;
    let yPos = 20;

    const checkPage = (needed: number) => {
      if (yPos + needed > 275) { doc.addPage(); yPos = 20; }
    };

    const addSection = (title: string) => {
      checkPage(20);
      yPos += 6;
      doc.setFontSize(14);
      doc.setTextColor(34, 197, 94);
      doc.text(title, margin, yPos);
      yPos += 10;
      doc.setFontSize(10);
      doc.setTextColor(40, 40, 40);
    };

    const addLine = (text: string, indent = 0, fontSize = 10, color: [number, number, number] = [40, 40, 40]) => {
      doc.setFontSize(fontSize);
      doc.setTextColor(...color);
      const lines = doc.splitTextToSize(text, maxWidth - indent);
      lines.forEach((line: string) => {
        checkPage(6);
        doc.text(line, margin + indent, yPos);
        yPos += fontSize * 0.55;
      });
    };

    // ── Title ──
    doc.setFontSize(22);
    doc.setTextColor(34, 197, 94);
    doc.text("HAAutomation Security Report", margin, yPos);
    yPos += 12;

    // ── Scan Info ──
    if (scanSummary) {
      doc.setFontSize(10);
      doc.setTextColor(80, 80, 80);
      doc.text(`Domain: ${scanSummary.domain}`, margin, yPos); yPos += 6;
      doc.text(`Scan Type: ${scanSummary.scanType.toUpperCase()}`, margin, yPos); yPos += 6;
      doc.text(`Date: ${new Date(scanSummary.timestamp).toLocaleString()}`, margin, yPos); yPos += 10;

      // ── DNS Records ──
      if (scanSummary.results.dnsRecords) {
        addSection("DNS Records");
        const dns = scanSummary.results.dnsRecords;
        for (const [type, records] of Object.entries(dns)) {
          if ((records as string[]).length > 0) {
            (records as string[]).forEach((r: string) => {
              addLine(`${type}: ${r}`, 5);
            });
          }
        }
      }

      // ── Subdomains ──
      if (scanSummary.results.subdomains?.length > 0) {
        addSection(`Discovered Subdomains (${scanSummary.results.totalSubdomains})`);
        scanSummary.results.subdomains.forEach((sub: string) => {
          addLine(`• ${sub}`, 5);
        });
      }

      // ── Open Ports with Criticality ──
      if (scanSummary.results.openPorts?.length > 0) {
        addSection(`Open Ports (${scanSummary.results.totalOpenPorts})`);

        const portDescriptions: Record<string, string> = {
          'FTP Data': 'File Transfer Protocol data channel',
          'FTP': 'File Transfer Protocol - file uploads/downloads, may expose sensitive data',
          'SSH': 'Secure Shell - remote server access, should be secured with keys',
          'Telnet': 'Unencrypted remote access - CRITICAL: should be disabled, use SSH instead',
          'SMTP': 'Simple Mail Transfer Protocol - used for outgoing mail',
          'SMTP Submission': 'Email submission port for authenticated clients',
          'DNS': 'Domain Name System - translates domain names to IP addresses',
          'HTTP': 'Web traffic - unencrypted, should redirect to HTTPS',
          'POP3': 'Email retrieval - consider using secure version (POP3S)',
          'IMAP': 'Email access - consider using secure version (IMAPS)',
          'HTTPS': 'Secure web traffic - encrypted communication',
          'SMTPS': 'Secure email sending - encrypted SMTP',
          'IMAPS': 'Secure email access - encrypted IMAP',
          'POP3S': 'Secure email retrieval - encrypted POP3',
          'MSSQL': 'Microsoft SQL Server - should NOT be publicly exposed',
          'MySQL': 'MySQL database - should NOT be publicly exposed',
          'RDP': 'Remote Desktop Protocol - frequently targeted by attackers',
          'PostgreSQL': 'PostgreSQL database - should NOT be publicly exposed',
          'VNC': 'Virtual Network Computing - remote desktop, often unencrypted',
          'Redis': 'Redis cache/database - should NOT be publicly exposed',
          'HTTP Proxy': 'HTTP Proxy/Alt port - web server or proxy service',
          'HTTPS Alt': 'Alternative HTTPS port - secure web server',
          'MongoDB': 'MongoDB database - should NOT be publicly exposed',
          'Dev Server': 'Development server - should NOT be in production',
          'Elasticsearch': 'Elasticsearch - should NOT be publicly exposed',
          'Elasticsearch Transport': 'Elasticsearch transport - internal only',
          'Memcached': 'Memcached cache - should NOT be publicly exposed',
        };

        scanSummary.results.openPorts.forEach((port: any) => {
          checkPage(20);
          const critIcon = port.criticality === 'CRITICAL' ? '[CRITICAL]' : port.criticality === 'HIGH' ? '[HIGH]' : port.criticality === 'MEDIUM' ? '[MEDIUM]' : '[LOW]';
          const critColor: [number, number, number] = port.criticality === 'CRITICAL' ? [220, 38, 38] : port.criticality === 'HIGH' ? [234, 88, 12] : port.criticality === 'MEDIUM' ? [202, 138, 4] : [34, 197, 94];

          addLine(`Port ${port.port} - ${port.service} ${critIcon}`, 5, 11, critColor);
          const desc = portDescriptions[port.service] || 'Service requires investigation';
          addLine(desc, 10, 9, [100, 100, 100]);
          yPos += 3;
        });
      }

      // ── Security Headers ──
      if (scanSummary.results.securityHeaders && Object.keys(scanSummary.results.securityHeaders).length > 0) {
        addSection("Security Headers");
        for (const [name, value] of Object.entries(scanSummary.results.securityHeaders)) {
          const present = value !== 'Not set';
          const color: [number, number, number] = present ? [34, 197, 94] : [220, 38, 38];
          addLine(`${present ? '✓' : '✗'} ${name}: ${value}`, 5, 9, color);
        }
      }

      // ── Technologies ──
      if (scanSummary.results.technologies?.length > 0) {
        addSection("Detected Technologies");
        scanSummary.results.technologies.forEach((tech: string) => {
          addLine(`• ${tech}`, 5);
        });
      }

      // ── Vulnerable Paths ──
      if (scanSummary.results.vulnerablePaths?.length > 0) {
        addSection("Sensitive Paths Discovered");
        scanSummary.results.vulnerablePaths.forEach((vp: any) => {
          addLine(`${vp.path} - ${vp.risk} (HTTP ${vp.status})`, 5, 9, [220, 38, 38]);
        });
      }

      // ── HTTP Methods ──
      if (scanSummary.results.httpMethods?.length > 0) {
        addSection("HTTP Methods Allowed");
        addLine(scanSummary.results.httpMethods.join(', '), 5);
      }
    }

    // ── AI Analysis Report ──
    if (aiReport) {
      addSection("AI Security Analysis");
      // Parse markdown to plain text for PDF
      const plainText = aiReport
        .replace(/#{1,6}\s+/g, '\n')       // headers → newlines
        .replace(/\*\*(.+?)\*\*/g, '$1')    // bold
        .replace(/\*(.+?)\*/g, '$1')        // italic
        .replace(/`(.+?)`/g, '$1')          // inline code
        .replace(/```[\s\S]*?```/g, '')     // code blocks
        .replace(/\[(.+?)\]\(.+?\)/g, '$1') // links
        .replace(/^\s*[-*]\s+/gm, '• ')     // bullets
        .replace(/^\s*\d+\.\s+/gm, '')      // numbered lists
        .replace(/\n{3,}/g, '\n\n')         // multiple newlines
        .trim();

      const paragraphs = plainText.split('\n');
      for (const para of paragraphs) {
        const trimmed = para.trim();
        if (!trimmed) { yPos += 3; continue; }

        // Detect section-like lines (short, no punctuation at end)
        if (trimmed.length < 60 && !trimmed.endsWith('.') && !trimmed.startsWith('•') && !trimmed.startsWith('-')) {
          checkPage(12);
          doc.setFontSize(11);
          doc.setTextColor(34, 197, 94);
          doc.text(trimmed, margin + 5, yPos);
          yPos += 7;
        } else {
          addLine(trimmed, 5, 9, [60, 60, 60]);
        }
      }
    }

    // ── Scan Log ──
    checkPage(20);
    addSection("Detailed Scan Log");
    doc.setFontSize(7);
    doc.setTextColor(80, 80, 80);
    messages.forEach((msg) => {
      const text = `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.message}`;
      const lines = doc.splitTextToSize(text, maxWidth);
      lines.forEach((line: string) => {
        checkPage(4);
        doc.text(line, margin, yPos);
        yPos += 4;
      });
    });

    doc.save(`haautomation-scan-${scanSummary?.domain || 'report'}-${Date.now()}.pdf`);
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-6 h-6 text-primary" />
          <h2 className="text-2xl font-bold text-foreground">Scan Results</h2>
        </div>
        <div className="flex gap-2">
          {scanSummary && (
            <Button onClick={generatePDF} className="bg-secondary hover:bg-secondary/90 text-secondary-foreground">
              <Download className="w-4 h-4 mr-2" />
              Export PDF {aiReport ? '(with AI Analysis)' : ''}
            </Button>
          )}
          <Button onClick={onReset} variant="outline" className="border-primary/30 text-foreground hover:bg-primary/10">
            New Scan
          </Button>
        </div>
      </div>

      <Card className="bg-terminal-bg border-primary/20 overflow-hidden">
        <div ref={resultsRef} className="p-6 font-mono text-sm space-y-1 max-h-[600px] overflow-y-auto custom-scrollbar">
          {messages.length === 0 && isScanning && (
            <div className="text-terminal-text animate-pulse">Initializing scan...</div>
          )}
          {messages.map((msg, idx) => (
            <div key={idx} className={`${getMessageColor(msg.type)} transition-all duration-300`}>
              <span className="text-terminal-accent mr-2">[{new Date(msg.timestamp).toLocaleTimeString()}]</span>
              {msg.message}
            </div>
          ))}
          {isScanning && (
            <div className="text-primary animate-pulse mt-2">▊ Scanning...</div>
          )}
        </div>
      </Card>

      {scanSummary && !isScanning && (
        <AISecurityReport scanSummary={scanSummary} onReportGenerated={handleAiReportGenerated} />
      )}

      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 8px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: hsl(var(--terminal-bg)); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: hsl(var(--primary)); border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: hsl(var(--secondary)); }
      `}</style>
    </div>
  );
};

export default ScanResults;
