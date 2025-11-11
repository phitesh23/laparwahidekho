import { useState } from "react";
import ScanForm from "@/components/ScanForm";
import ScanResults from "@/components/ScanResults";
import { useToast } from "@/hooks/use-toast";

interface ScanMessage {
  message: string;
  type: string;
  timestamp: string;
}

const Index = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [messages, setMessages] = useState<ScanMessage[]>([]);
  const [scanSummary, setScanSummary] = useState<any>(null);
  const { toast } = useToast();

  const startScan = async (domain: string, scanType: string) => {
    setIsScanning(true);
    setMessages([]);
    setScanSummary(null);

    try {
      const response = await fetch(
        `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/security-scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`,
          },
          body: JSON.stringify({ domain, scanType }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to start scan");
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error("No response body");
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === "summary") {
                setScanSummary(data.data);
              } else {
                setMessages((prev) => [...prev, data]);
              }
            } catch (e) {
              console.error("Failed to parse message:", e);
            }
          }
        }
      }

      toast({
        title: "Scan Complete",
        description: "Security scan completed successfully. You can now export the results.",
      });
    } catch (error) {
      console.error("Scan error:", error);
      toast({
        title: "Scan Failed",
        description: "An error occurred during the scan. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const resetScan = () => {
    setMessages([]);
    setScanSummary(null);
    setIsScanning(false);
  };

  return (
    <div className="min-h-screen bg-background py-12 px-4">
      {messages.length === 0 ? (
        <ScanForm onStartScan={startScan} isScanning={isScanning} />
      ) : (
        <ScanResults
          messages={messages}
          isScanning={isScanning}
          scanSummary={scanSummary}
          onReset={resetScan}
        />
      )}
    </div>
  );
};

export default Index;
