import { useEffect, useRef } from "react";
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

  useEffect(() => {
    if (resultsRef.current) {
      resultsRef.current.scrollTop = resultsRef.current.scrollHeight;
    }
  }, [messages]);

  const getMessageColor = (type: string) => {
    switch (type) {
      case 'success':
        return 'text-primary';
      case 'warning':
        return 'text-warning';
      case 'error':
      case 'critical':
        return 'text-critical';
      case 'header':
        return 'text-secondary font-bold';
      case 'scan':
        return 'text-muted-foreground';
      default:
        return 'text-terminal-text';
    }
  };

  const generatePDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 20;
    let yPos = 20;

    // Title
    doc.setFontSize(20);
    doc.setTextColor(34, 197, 94);
    doc.text("HAAutomation Security Scan Report", margin, yPos);
    yPos += 15;

    // Scan Info
    doc.setFontSize(12);
    doc.setTextColor(0, 0, 0);
    if (scanSummary) {
      doc.text(`Domain: ${scanSummary.domain}`, margin, yPos);
      yPos += 8;
      doc.text(`Scan Type: ${scanSummary.scanType.toUpperCase()}`, margin, yPos);
      yPos += 8;
      doc.text(`Date: ${new Date(scanSummary.timestamp).toLocaleString()}`, margin, yPos);
      yPos += 15;

      // Results Summary
      doc.setFontSize(14);
      doc.setTextColor(34, 197, 94);
      doc.text("Results Summary", margin, yPos);
      yPos += 10;

      doc.setFontSize(10);
      doc.setTextColor(0, 0, 0);
      doc.text(`Total Subdomains Found: ${scanSummary.results.totalSubdomains}`, margin, yPos);
      yPos += 8;
      doc.text(`Total Open Ports: ${scanSummary.results.totalOpenPorts}`, margin, yPos);
      yPos += 15;

      // Subdomains
      if (scanSummary.results.subdomains.length > 0) {
        doc.setFontSize(12);
        doc.setTextColor(34, 197, 94);
        doc.text("Discovered Subdomains:", margin, yPos);
        yPos += 8;

        doc.setFontSize(9);
        doc.setTextColor(0, 0, 0);
        scanSummary.results.subdomains.forEach((subdomain: string) => {
          if (yPos > 270) {
            doc.addPage();
            yPos = 20;
          }
          doc.text(`• ${subdomain}`, margin + 5, yPos);
          yPos += 6;
        });
        yPos += 10;
      }

      // Open Ports
      if (scanSummary.results.openPorts.length > 0) {
        if (yPos > 250) {
          doc.addPage();
          yPos = 20;
        }
        doc.setFontSize(12);
        doc.setTextColor(34, 197, 94);
        doc.text("Open Ports Discovered:", margin, yPos);
        yPos += 8;

        const portDescriptions: Record<string, string> = {
          'FTP Data': 'File Transfer Protocol data channel - allows file transfers',
          'FTP': 'File Transfer Protocol - allows file uploads/downloads, may expose sensitive data',
          'SSH': 'Secure Shell - remote server access, should be secured with keys',
          'Telnet': 'Unencrypted remote access - CRITICAL: should be disabled, use SSH instead',
          'SMTP': 'Email sending - used for outgoing mail',
          'DNS': 'Domain Name System - translates domain names to IP addresses',
          'HTTP': 'Web traffic - unencrypted, should redirect to HTTPS',
          'POP3': 'Email retrieval - consider using secure version (POP3S)',
          'IMAP': 'Email access - consider using secure version (IMAPS)',
          'HTTPS': 'Secure web traffic - encrypted communication',
          'SMTPS': 'Secure email sending - encrypted SMTP',
          'IMAPS': 'Secure email access - encrypted IMAP',
          'POP3S': 'Secure email retrieval - encrypted POP3',
          'MSSQL': 'Microsoft SQL Server database - should not be publicly exposed',
          'MySQL': 'MySQL database - should not be publicly exposed',
          'RDP': 'Remote Desktop Protocol - Windows remote access, often targeted',
          'PostgreSQL': 'PostgreSQL database - should not be publicly exposed',
          'VNC': 'Virtual Network Computing - remote desktop access',
          'Redis': 'Redis database cache - should not be publicly exposed',
          'HTTP Alt': 'Alternative HTTP port - web server or proxy',
          'HTTPS Alt': 'Alternative HTTPS port - secure web server',
          'MongoDB': 'MongoDB database - should not be publicly exposed',
          'Node.js': 'Node.js application - common development port',
          'Unknown': 'Service not identified - requires further investigation'
        };

        doc.setFontSize(9);
        doc.setTextColor(0, 0, 0);
        scanSummary.results.openPorts.forEach((port: any) => {
          if (yPos > 265) {
            doc.addPage();
            yPos = 20;
          }
          
          const description = portDescriptions[port.service] || 'Service usage unknown';
          
          // Port header line
          const portHeader = `Port ${port.port} - ${port.service}`;
          doc.text(portHeader, margin + 5, yPos);
          yPos += 6;
          
          // Description with proper text wrapping
          doc.setFontSize(8);
          doc.setTextColor(80, 80, 80);
          const descLines = doc.splitTextToSize(description, pageWidth - 2 * margin - 10);
          descLines.forEach((line: string) => {
            if (yPos > 275) {
              doc.addPage();
              yPos = 20;
            }
            doc.text(line, margin + 10, yPos);
            yPos += 5;
          });
          
          // Reset for next port
          doc.setFontSize(9);
          doc.setTextColor(0, 0, 0);
          yPos += 4;
        });
      }
    }

    // Scan Log
    if (yPos > 200) {
      doc.addPage();
      yPos = 20;
    }
    doc.setFontSize(12);
    doc.setTextColor(34, 197, 94);
    doc.text("Detailed Scan Log:", margin, yPos);
    yPos += 10;

    doc.setFontSize(8);
    doc.setTextColor(0, 0, 0);
    messages.forEach((msg) => {
      if (yPos > 280) {
        doc.addPage();
        yPos = 20;
      }
      const text = `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.message}`;
      const lines = doc.splitTextToSize(text, pageWidth - 2 * margin);
      lines.forEach((line: string) => {
        if (yPos > 280) {
          doc.addPage();
          yPos = 20;
        }
        doc.text(line, margin, yPos);
        yPos += 5;
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
            <Button
              onClick={generatePDF}
              className="bg-secondary hover:bg-secondary/90 text-secondary-foreground"
            >
              <Download className="w-4 h-4 mr-2" />
              Export PDF
            </Button>
          )}
          <Button
            onClick={onReset}
            variant="outline"
            className="border-primary/30 text-foreground hover:bg-primary/10"
          >
            New Scan
          </Button>
        </div>
      </div>

      <Card className="bg-terminal-bg border-primary/20 overflow-hidden">
        <div
          ref={resultsRef}
          className="p-6 font-mono text-sm space-y-1 max-h-[600px] overflow-y-auto custom-scrollbar"
        >
          {messages.length === 0 && isScanning && (
            <div className="text-terminal-text animate-pulse">
              Initializing scan...
            </div>
          )}
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`${getMessageColor(msg.type)} transition-all duration-300`}
            >
              <span className="text-terminal-accent mr-2">
                [{new Date(msg.timestamp).toLocaleTimeString()}]
              </span>
              {msg.message}
            </div>
          ))}
          {isScanning && (
            <div className="text-primary animate-pulse mt-2">
              ▊ Scanning...
            </div>
          )}
        </div>
      </Card>

      {scanSummary && !isScanning && (
        <AISecurityReport scanSummary={scanSummary} />
      )}
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: hsl(var(--terminal-bg));
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: hsl(var(--primary));
          border-radius: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: hsl(var(--secondary));
        }
      `}</style>
    </div>
  );
};

export default ScanResults;
