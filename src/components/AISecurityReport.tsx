import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Brain, Loader2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useToast } from "@/hooks/use-toast";

interface AISecurityReportProps {
  scanSummary: any;
}

const AISecurityReport = ({ scanSummary }: AISecurityReportProps) => {
  const [report, setReport] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [hasGenerated, setHasGenerated] = useState(false);
  const { toast } = useToast();

  const generateReport = async () => {
    setIsGenerating(true);
    setReport("");

    try {
      const response = await fetch(
        `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/ai-security-report`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scanSummary }),
        }
      );

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to generate report");
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error("No response stream");

      const decoder = new TextDecoder();
      let buffer = "";
      let fullReport = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        let newlineIdx: number;
        while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
          let line = buffer.slice(0, newlineIdx);
          buffer = buffer.slice(newlineIdx + 1);

          if (line.endsWith("\r")) line = line.slice(0, -1);
          if (line.startsWith(":") || line.trim() === "") continue;
          if (!line.startsWith("data: ")) continue;

          const jsonStr = line.slice(6).trim();
          if (jsonStr === "[DONE]") break;

          try {
            const parsed = JSON.parse(jsonStr);
            const content = parsed.choices?.[0]?.delta?.content;
            if (content) {
              fullReport += content;
              setReport(fullReport);
            }
          } catch {
            buffer = line + "\n" + buffer;
            break;
          }
        }
      }

      setHasGenerated(true);
    } catch (error) {
      console.error("AI report error:", error);
      toast({
        title: "Report Generation Failed",
        description: error instanceof Error ? error.message : "Could not generate AI report",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-4">
      {!hasGenerated && !isGenerating && (
        <Button
          onClick={generateReport}
          className="w-full bg-accent hover:bg-accent/90 text-accent-foreground font-semibold py-6 text-lg shadow-[var(--shadow-glow)] transition-all"
        >
          <Brain className="w-5 h-5 mr-2" />
          Generate AI Security Report
        </Button>
      )}

      {isGenerating && !report && (
        <Card className="p-6 border-primary/20 bg-card/50">
          <div className="flex items-center gap-3 text-primary">
            <Loader2 className="w-5 h-5 animate-spin" />
            <span className="font-mono text-sm">AI is analyzing your scan results...</span>
          </div>
        </Card>
      )}

      {report && (
        <Card className="border-primary/20 bg-card/50 overflow-hidden">
          <div className="p-4 border-b border-primary/20 flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-bold text-foreground">AI Security Analysis Report</h3>
            {isGenerating && <Loader2 className="w-4 h-4 animate-spin text-primary ml-auto" />}
          </div>
          <div className="p-6 prose prose-invert prose-sm max-w-none
            prose-headings:text-primary prose-headings:font-bold
            prose-h1:text-2xl prose-h2:text-xl prose-h3:text-lg
            prose-strong:text-foreground
            prose-p:text-muted-foreground prose-p:leading-relaxed
            prose-li:text-muted-foreground
            prose-code:text-secondary prose-code:bg-muted prose-code:px-1 prose-code:rounded
            prose-a:text-secondary prose-a:underline
            prose-table:border-primary/20
            prose-th:text-foreground prose-th:border-primary/20 prose-th:p-2
            prose-td:text-muted-foreground prose-td:border-primary/20 prose-td:p-2
          ">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
          </div>
        </Card>
      )}

      {hasGenerated && !isGenerating && (
        <Button
          onClick={generateReport}
          variant="outline"
          className="border-primary/30 text-foreground hover:bg-primary/10"
        >
          <Brain className="w-4 h-4 mr-2" />
          Regenerate Report
        </Button>
      )}
    </div>
  );
};

export default AISecurityReport;
