import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Shield, Zap, Radar } from "lucide-react";

interface ScanFormProps {
  onStartScan: (domain: string, scanType: string) => void;
  isScanning: boolean;
}

const ScanForm = ({ onStartScan, isScanning }: ScanFormProps) => {
  const [domain, setDomain] = useState("");
  const [selectedScan, setSelectedScan] = useState("quick");
  const [domainError, setDomainError] = useState("");

  const scanTypes = [
    {
      id: "quick",
      name: "Quick Scan",
      icon: Zap,
      description: "Fast overview of main vulnerabilities",
      duration: "~30 seconds",
    },
    {
      id: "detailed",
      name: "Detailed Scan",
      icon: Shield,
      description: "Comprehensive security analysis",
      duration: "~1 minute",
    },
    {
      id: "full",
      name: "Full Scan",
      icon: Radar,
      description: "Deep dive into all security aspects",
      duration: "~2 minutes",
    },
  ];

  const validateDomain = (value: string): boolean => {
    if (!value.trim()) {
      setDomainError("");
      return false;
    }

    // Check if it's a valid domain or URL format
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const urlRegex = /^(?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\/.*)?$/;
    
    if (!domainRegex.test(value) && !urlRegex.test(value)) {
      setDomainError("Input a valid url");
      return false;
    }
    
    setDomainError("");
    return true;
  };

  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setDomain(value);
    if (value.trim()) {
      validateDomain(value);
    } else {
      setDomainError("");
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim() && validateDomain(domain.trim())) {
      onStartScan(domain.trim(), selectedScan);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      <div className="text-center space-y-2">
        <h1 className="text-5xl font-bold bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent border-secondary bg-destructive-foreground">
          Automated Vulnerability Scanner
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced Security Scanning Platform
        </p>
      </div>

      <Card className="p-6 border-primary/20 bg-card/50 backdrop-blur">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label htmlFor="domain" className="text-sm font-medium text-foreground">
              Target Domain
            </label>
            <Input
              id="domain"
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={handleDomainChange}
              className={`bg-input border-primary/30 text-foreground placeholder:text-muted-foreground font-mono ${
                domainError ? "border-destructive" : ""
              }`}
              disabled={isScanning}
            />
            {domainError && (
              <p className="text-sm text-destructive font-medium">{domainError}</p>
            )}
          </div>

          <div className="space-y-3">
            <label className="text-sm font-medium text-foreground">
              Select Scan Type
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {scanTypes.map((scan) => {
                const Icon = scan.icon;
                return (
                  <button
                    key={scan.id}
                    type="button"
                    onClick={() => setSelectedScan(scan.id)}
                    disabled={isScanning}
                    className={`p-4 rounded-lg border-2 transition-all text-left ${
                      selectedScan === scan.id
                        ? "border-primary bg-primary/10 shadow-[0_0_20px_rgba(34,197,94,0.3)]"
                        : "border-border bg-card hover:border-primary/50"
                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    <div className="flex items-start gap-3">
                      <Icon className={`w-6 h-6 mt-1 ${selectedScan === scan.id ? "text-primary" : "text-muted-foreground"}`} />
                      <div className="space-y-1 flex-1">
                        <h3 className={`font-semibold ${selectedScan === scan.id ? "text-primary" : "text-foreground"}`}>
                          {scan.name}
                        </h3>
                        <p className="text-xs text-muted-foreground">
                          {scan.description}
                        </p>
                        <p className="text-xs text-secondary font-mono">
                          {scan.duration}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <Button
            type="submit"
            disabled={!domain.trim() || isScanning || !!domainError}
            className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-6 text-lg shadow-[0_0_20px_rgba(34,197,94,0.4)] hover:shadow-[0_0_30px_rgba(34,197,94,0.6)] transition-all"
          >
            {isScanning ? "Scanning..." : "Start Security Scan"}
          </Button>
        </form>
      </Card>
    </div>
  );
};

export default ScanForm;
