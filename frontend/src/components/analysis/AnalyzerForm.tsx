import React, { useState } from "react";
import { AnalysisRequest, AuthStatus } from "../../types/analysis";
import { AlertCircle, Plus, Trash2, ShieldAlert, Sparkles, RefreshCw, ClipboardPaste, Check, Globe } from "lucide-react";

interface AnalyzerFormProps {
  onSubmit: (request: AnalysisRequest) => void;
  isLoading: boolean;
  error: string | null;
}

export const AnalyzerForm: React.FC<AnalyzerFormProps> = ({ onSubmit, isLoading, error }) => {
  const [rawText, setRawText] = useState("");
  const [senderEmail, setSenderEmail] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [urls, setUrls] = useState<string[]>([]);
  const [newUrl, setNewUrl] = useState("");
  const [spf, setSpf] = useState<AuthStatus>("unknown");
  const [dkim, setDkim] = useState<AuthStatus>("unknown");
  const [dmarc, setDmarc] = useState<AuthStatus>("unknown");
  const [parseSuccessMessage, setParseSuccessMessage] = useState<string | null>(null);

  // Core parsing engine
  const parseRawEmailText = (text: string, extraHtml?: string) => {
    if (!text.trim() && !extraHtml) return;

    let detectedSender = "";
    let detectedReplyTo = "";
    let detectedSubject = "";
    let detectedSpf: AuthStatus = "unknown";
    let detectedDkim: AuthStatus = "unknown";
    let detectedDmarc: AuthStatus = "unknown";

    // 1. Extract From / Sender
    const fromMatch = text.match(/(?:from\s*:|sender\s*:)\s*([^<\n\r]+<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/i);
    if (fromMatch && fromMatch[2]) {
      detectedSender = fromMatch[2].trim();
    } else {
      const firstEmailMatch = text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
      if (firstEmailMatch) {
        detectedSender = firstEmailMatch[1].trim();
      }
    }

    // 2. Extract Reply-To
    const replyToMatch = text.match(/(?:reply-to\s*:)\s*([^<\n\r]+<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/i);
    if (replyToMatch && replyToMatch[2]) {
      detectedReplyTo = replyToMatch[2].trim();
    }

    // 3. Extract Subject
    const subjectMatch = text.match(/(?:subject\s*:)\s*([^\n\r]+)/i);
    if (subjectMatch && subjectMatch[1]) {
      detectedSubject = subjectMatch[1].trim();
    }

    // 4. Extract Auth signals
    if (/spf\s*:\s*pass|mailed-by:/i.test(text)) detectedSpf = "pass";
    else if (/spf\s*:\s*fail/i.test(text)) detectedSpf = "fail";

    if (/dkim\s*:\s*pass|signed-by:/i.test(text)) detectedDkim = "pass";
    else if (/dkim\s*:\s*fail/i.test(text)) detectedDkim = "fail";

    if (/dmarc\s*:\s*pass/i.test(text)) detectedDmarc = "pass";
    else if (/dmarc\s*:\s*fail/i.test(text)) detectedDmarc = "fail";

    // 5. Extract URLs from Plain Text AND Hidden HTML Clipboard data
    const urlMatches = new Set<string>();

    // A. Check plain text
    const plainMatches = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    plainMatches.forEach(u => urlMatches.add(u.trim()));

    // B. Check hidden HTML hyperlinks (e.g. <a href="https://hidden-site.com">Click Here</a>)
    if (extraHtml) {
      const parser = new DOMParser();
      const doc = parser.parseFromString(extraHtml, "text/html");
      const anchors = doc.querySelectorAll("a[href]");
      anchors.forEach(a => {
        const href = a.getAttribute("href");
        if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
          urlMatches.add(href.trim());
        }
      });
    }

    const extractedUrls = Array.from(urlMatches).slice(0, 50);

    // 6. Extract Clean Body (strip common header prefixes)
    const lines = text.split(/\r?\n/);
    const bodyLines = lines.filter(line => {
      const trimmed = line.trim().toLowerCase();
      if (trimmed.startsWith("from:") || trimmed.startsWith("reply-to:") || trimmed.startsWith("to:") || 
          trimmed.startsWith("subject:") || trimmed.startsWith("date:") || trimmed.startsWith("mailed-by:") || 
          trimmed.startsWith("signed-by:") || trimmed.startsWith("security:")) {
        return false;
      }
      return true;
    });

    const parsedBody = bodyLines.join("\n").trim();
    const detectedBody = parsedBody.length > 0 ? parsedBody : text;

    // Apply to state
    if (detectedSender) setSenderEmail(detectedSender);
    if (detectedReplyTo) setReplyTo(detectedReplyTo);
    if (detectedSubject) setSubject(detectedSubject);
    setBody(detectedBody);
    setSpf(detectedSpf);
    setDkim(detectedDkim);
    setDmarc(detectedDmarc);
    if (extractedUrls.length > 0) {
      setUrls(extractedUrls);
    }

    setParseSuccessMessage(`Auto-parsed email headers & recovered ${extractedUrls.length} hidden hyperlink(s).`);
    setTimeout(() => setParseSuccessMessage(null), 4000);
  };

  // Intercept paste event to read both text and clipboard HTML
  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const textData = e.clipboardData.getData("text/plain");
    const htmlData = e.clipboardData.getData("text/html");

    // Standard text in the box
    setRawText(textData);
    // Parse using both plain text and rich clipboard HTML
    parseRawEmailText(textData, htmlData);
  };

  const handleRawTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setRawText(val);
    parseRawEmailText(val);
  };

  const handleAddUrl = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) return;
    if (urls.length >= 50) return;
    setUrls([...urls, newUrl.trim()]);
    setNewUrl("");
  };

  const handleRemoveUrl = (index: number) => {
    setUrls(urls.filter((_, i) => i !== index));
  };

  const handleLoadPhishingDemo = () => {
    const rawPhish = `from:Security Alert <security-alert@paypa1.com>
reply-to:"PayPal Recovery" <attacker-inbox@suspicious-domain.com>
subject:Urgent: Account Suspension Notice
date:Oct 24, 2026, 9:15 AM
spf:fail
dkim:none
dmarc:fail

Dear Customer, please verify your credentials within 24 hours: https://paypal.com.attacker-portal.net/login
Failure to confirm your identity will result in permanent account termination.`;

    setRawText(rawPhish);
    setSenderEmail("security-alert@paypa1.com");
    setReplyTo("attacker-inbox@suspicious-domain.com");
    setSubject("Urgent: Account Suspension Notice");
    setBody("Dear Customer, please verify your credentials within 24 hours: https://paypal.com.attacker-portal.net/login\nFailure to confirm your identity will result in permanent account termination.");
    setUrls(["https://paypal.com.attacker-portal.net/login"]);
    setSpf("fail");
    setDkim("none");
    setDmarc("fail");
  };

  const handleLoadCleanDemo = () => {
    const rawClean = `from:Naukri.com <donotreply_mailer@naukri.com>
reply-to:"Naukri.com" <donotreply_mailer@naukri.com>
to:vineet.bisht25101992@gmail.com
date:Oct 23, 2026, 4:25 PM
subject:You have 2 new jobs in your inbox!
mailed-by:naukri.com
signed-by:naukri.com
security:Standard encryption (TLS)

Hi Vineet Singh Bisht, Apply to these new jobs directly sent by recruiters:
Data BA Hyderabad,Bengaluru,Pune 6 - 11 Years ₹ 30.0 - 45.0 LPA libcap1
Data Scientist New Delhi,Gurugram 2 - 5 Years ₹ 35.0 - 50.0 LPA Ramfincorp
View all jobs: https://www.naukri.com
Please do not pay any money to anyone who promises to find you a job. IEIL shall not have any responsibility in this regard.`;

    setRawText(rawClean);
    setSenderEmail("donotreply_mailer@naukri.com");
    setReplyTo("donotreply_mailer@naukri.com");
    setSubject("You have 2 new jobs in your inbox!");
    setBody(`Hi Vineet Singh Bisht, Apply to these new jobs directly sent by recruiters:
Data BA Hyderabad,Bengaluru,Pune 6 - 11 Years ₹ 30.0 - 45.0 LPA libcap1
Data Scientist New Delhi,Gurugram 2 - 5 Years ₹ 35.0 - 50.0 LPA Ramfincorp
View all jobs: https://www.naukri.com
Please do not pay any money to anyone who promises to find you a job. IEIL shall not have any responsibility in this regard.`);
    setUrls(["https://www.naukri.com"]);
    setSpf("pass");
    setDkim("pass");
    setDmarc("pass");
  };

  const handleClear = () => {
    setRawText("");
    setSenderEmail("");
    setReplyTo("");
    setSubject("");
    setBody("");
    setUrls([]);
    setNewUrl("");
    setSpf("unknown");
    setDkim("unknown");
    setDmarc("unknown");
    setParseSuccessMessage(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!senderEmail.trim()) return;

    onSubmit({
      sender_email: senderEmail.trim(),
      reply_to: replyTo.trim() || undefined,
      subject: subject.trim(),
      body: body,
      additional_urls: urls,
      authentication: {
        spf,
        dkim,
        dmarc,
      },
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Top Helper Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl border border-cyber-700/60 bg-cyber-900/60">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="text-xs text-slate-300 font-medium">Quick Test: Load sample email</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleLoadPhishingDemo}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 transition-colors"
          >
            Load Phishing Demo
          </button>
          <button
            type="button"
            onClick={handleLoadCleanDemo}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors"
          >
            Load Legitimate Demo
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-cyber-800 text-slate-400 hover:text-white border border-cyber-700 transition-colors"
          >
            Clear All
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-950/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-rose-200 leading-relaxed">{error}</div>
        </div>
      )}

      {/* Quick Paste Area with Automatic Rich Hyperlink Recovery */}
      <div className="p-5 rounded-2xl border border-cyan-500/30 bg-cyber-900/60 shadow-lg shadow-cyan-950/20 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ClipboardPaste className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Quick Paste — Copy-Paste Directly from Email
            </h3>
          </div>
          <span className="text-[11px] font-mono text-cyan-400/80">Auto-Extracts Hidden Hyperlinks</span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Select and copy the email text in Gmail or Outlook, then paste it here. Hidden hyperlinks behind words like <span className="text-cyan-300 font-mono">"Click Here"</span> or buttons are automatically extracted and scanned for threats.
        </p>

        <textarea
          rows={5}
          value={rawText}
          onPaste={handlePaste}
          onChange={handleRawTextChange}
          placeholder="Paste copied email here (Ctrl + V)..."
          className="w-full px-3.5 py-2.5 rounded-xl bg-cyber-950 border border-cyber-700 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono text-xs leading-relaxed"
        />

        {parseSuccessMessage && (
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium animate-fadeIn">
            <Check className="w-4 h-4" />
            <span>{parseSuccessMessage}</span>
          </div>
        )}
      </div>

      {/* Extracted Fields Review */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">
            Extracted Field Details
          </span>
          <span className="text-[11px] text-slate-500">Auto-filled • Editable if desired</span>
        </div>

        {/* Sender & Envelope */}
        <div className="p-5 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">1. Sender Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Sender Email Address <span className="text-cyan-400">*</span>
              </label>
              <input
                type="text"
                required
                value={senderEmail}
                onChange={(e) => setSenderEmail(e.target.value)}
                placeholder="e.g. donotreply_mailer@naukri.com"
                className="w-full px-3.5 py-2.5 rounded-xl bg-cyber-950 border border-cyber-700 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Reply-To Address <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                type="text"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                placeholder="e.g. donotreply_mailer@naukri.com"
                className="w-full px-3.5 py-2.5 rounded-xl bg-cyber-950 border border-cyber-700 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>
          </div>
        </div>

        {/* Subject & Body */}
        <div className="p-5 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">2. Email Content</h3>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Subject Line</label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. You have 2 new jobs in your inbox!"
              maxLength={998}
              className="w-full px-3.5 py-2.5 rounded-xl bg-cyber-950 border border-cyber-700 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-slate-300">Clean Email Body</label>
              <span className="text-[11px] font-mono text-slate-500">{body.length.toLocaleString()} / 100,000 chars</span>
            </div>
            <textarea
              rows={5}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Email body text..."
              maxLength={100000}
              className="w-full px-3.5 py-2.5 rounded-xl bg-cyber-950 border border-cyber-700 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono leading-relaxed text-xs"
            />
          </div>
        </div>

        {/* Extracted URLs with Visual Inspection Flags */}
        <div className="p-5 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              3. Extracted URLs & Hyperlinks ({urls.length})
            </h3>
            <span className="text-[11px] text-slate-400">Scanned by Deterministic Rules & Random Forest ML</span>
          </div>

          <div className="flex gap-2">
            <input
              type="url"
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              placeholder="https://example.com/link"
              className="flex-1 px-3.5 py-2 rounded-xl bg-cyber-950 border border-cyber-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <button
              type="button"
              onClick={handleAddUrl}
              className="px-3.5 py-2 rounded-xl bg-cyber-800 hover:bg-cyber-700 text-cyan-400 border border-cyan-500/30 text-xs font-medium flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" /> Add Link
            </button>
          </div>

          {urls.length > 0 && (
            <div className="space-y-2 pt-2">
              {urls.map((u, i) => {
                const isInsecure = u.startsWith("http://");
                const hasIp = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(u);

                return (
                  <div key={i} className="flex items-center justify-between px-3.5 py-2 rounded-xl bg-cyber-950 border border-cyber-800 text-xs font-mono">
                    <div className="flex items-center gap-2 truncate max-w-xl">
                      <span className="text-slate-300 truncate">{u}</span>
                      {isInsecure && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/30">
                          HTTP (Insecure)
                        </span>
                      )}
                      {hasIp && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          IP-Literal Host
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleRemoveUrl(i)}
                      className="text-slate-500 hover:text-rose-400 p-1 flex-shrink-0"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Authentication Selectors */}
        <div className="p-5 rounded-2xl border border-cyber-700/60 bg-cyber-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">4. Email Authentication Statuses</h3>
            <span className="text-[11px] text-slate-500">Auto-detected or default to unknown</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">SPF Status</label>
              <select
                value={spf}
                onChange={(e) => setSpf(e.target.value as AuthStatus)}
                className="w-full px-3 py-2 rounded-xl bg-cyber-950 border border-cyber-700 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="unknown">unknown (neutral)</option>
                <option value="pass">pass (valid)</option>
                <option value="fail">fail (unauthorized)</option>
                <option value="none">none (no policy)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">DKIM Status</label>
              <select
                value={dkim}
                onChange={(e) => setDkim(e.target.value as AuthStatus)}
                className="w-full px-3 py-2 rounded-xl bg-cyber-950 border border-cyber-700 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="unknown">unknown (neutral)</option>
                <option value="pass">pass (valid)</option>
                <option value="fail">fail (invalid signature)</option>
                <option value="none">none (no signature)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">DMARC Status</label>
              <select
                value={dmarc}
                onChange={(e) => setDmarc(e.target.value as AuthStatus)}
                className="w-full px-3 py-2 rounded-xl bg-cyber-950 border border-cyber-700 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="unknown">unknown (neutral)</option>
                <option value="pass">pass (aligned)</option>
                <option value="fail">fail (alignment failed)</option>
                <option value="none">none (no policy)</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Submit Action */}
      <div className="pt-2">
        <button
          type="submit"
          disabled={isLoading || !senderEmail.trim()}
          className="w-full py-3.5 px-6 rounded-xl font-bold text-white bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2"
        >
          {isLoading ? (
            <>
              <RefreshCw className="w-5 h-5 animate-spin" />
              <span>Analyzing Email Signatures...</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-5 h-5" />
              <span>Run Phishing Risk Assessment</span>
            </>
          )}
        </button>
        <p className="text-center text-[11px] text-slate-500 mt-2">
          Note: This tool analyzes submitted information offline. A score of 0 does not certify that an email is legitimate.
        </p>
      </div>
    </form>
  );
};
