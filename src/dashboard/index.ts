import * as http from "http";
import * as crypto from "crypto";
import { SecurityScoreReport } from "../types";
import { AuditLogger } from "../core/audit-logger";

export interface DashboardInstance {
  server: http.Server;
  port: number;
  authToken: string;
  url: string;
  stop: () => Promise<void>;
}

function escapeHtml(unsafe: string): string {
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    if (parts.length >= 2) {
      list[parts[0].trim()] = decodeURIComponent(parts.slice(1).join("=").trim());
    }
  });
  return list;
}

export class DashboardServer {
  public static start(
    report: SecurityScoreReport, 
    preferredPort: number = 3840,
    auditLogger?: AuditLogger
  ): Promise<DashboardInstance> {
    return new Promise((resolve, reject) => {
      const authToken = crypto.randomBytes(32).toString("hex");
      const logger = auditLogger || new AuditLogger();

      const server = http.createServer((req, res) => {
        // AS-24: Explicit cache controls preventing credential or dashboard leak
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self';");

        // AS-24: Exact Host Header validation
        const rawHost = req.headers.host || "";
        const hostname = rawHost.split(":")[0].toLowerCase();
        if (hostname !== "127.0.0.1" && hostname !== "localhost") {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Forbidden: Invalid Host header" }));
          return;
        }

        const reqUrl = new URL(req.url || "/", `http://${req.headers.host}`);
        const cookies = parseCookies(req.headers.cookie);
        const queryToken = reqUrl.searchParams.get("token");
        const sessionToken = cookies["agentshield_session"];
        const bearerToken = req.headers["authorization"]?.replace(/^Bearer\s+/i, "");

        const isAuthenticated = (sessionToken === authToken) || (bearerToken === authToken) || (queryToken === authToken);

        if (!isAuthenticated) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unauthorized: Valid session cookie or Authorization header required" }));
          return;
        }

        // Set HttpOnly session cookie on authenticated requests if not yet set
        if (!sessionToken && isAuthenticated) {
          res.setHeader("Set-Cookie", `agentshield_session=${authToken}; HttpOnly; SameSite=Strict; Path=/`);
        }

        if (reqUrl.pathname === "/api/report") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(report));
          return;
        }

        if (reqUrl.pathname === "/api/audit") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(logger.getRecords()));
          return;
        }

        // Render Sanitized Dashboard UI HTML with immediate URL token stripping
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentShield Ultimate Security Dashboard</title>
  <script>
    // Immediately strip credentials from URL bar & history
    if (window.location.search && window.location.search.includes('token=')) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  </script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
    .score { font-size: 48px; font-weight: bold; color: ${report.score >= 80 ? "#22c55e" : report.score >= 60 ? "#eab308" : "#ef4444"}; }
    .grade { font-size: 28px; margin-left: 12px; color: #94a3b8; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .CRITICAL { background: #7f1d1d; color: #fca5a5; }
    .HIGH { background: #831843; color: #fbcfe8; }
    .MEDIUM { background: #713f12; color: #fef08a; }
    .LOW { background: #14532d; color: #bbf7d0; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-size: 13px; }
  </style>
</head>
<body>
  <h1>AgentShield Ultimate Security Dashboard</h1>
  <div class="card">
    <div style="display:flex; align-items:baseline;">
      <div class="score">${escapeHtml(String(report.score))} / 100</div>
      <div class="grade">Grade: ${escapeHtml(report.grade)}</div>
    </div>
    <p style="color:#94a3b8;">Total Tracked Findings: ${escapeHtml(String(report.totalFindings))} | Last Scan: ${escapeHtml(report.timestamp)}</p>
  </div>
  <div class="card">
    <h2>Security Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>Title</th><th>Resource</th></tr>
      </thead>
      <tbody>
        ${report.findings.map(f => `<tr>
          <td><span class="badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td>${escapeHtml(f.category)}</td>
          <td><strong>${escapeHtml(f.title)}</strong><br><small style="color:#94a3b8">${escapeHtml(f.evidence)}</small></td>
          <td><code>${escapeHtml(f.affectedResource)}</code></td>
        </tr>`).join("")}
      </tbody>
    </table>
  </div>
</body>
</html>`);
      });

      // Attach error listener before listen call to reject promise on port bind failure (AS-24)
      server.once("error", (err) => {
        reject(err);
      });

      server.listen(preferredPort, "127.0.0.1", () => {
        const address = server.address();
        const actualPort = typeof address === "object" && address ? address.port : preferredPort;
        const url = `http://127.0.0.1:${actualPort}/?token=${authToken}`;

        resolve({
          server,
          port: actualPort,
          authToken,
          url,
          stop: () => new Promise<void>((resStop) => {
            let stopped = false;
            const done = () => {
              if (!stopped) {
                stopped = true;
                resStop();
              }
            };
            try {
              if (typeof (server as any).closeAllConnections === "function") {
                (server as any).closeAllConnections();
              }
              if (typeof (server as any).closeIdleConnections === "function") {
                (server as any).closeIdleConnections();
              }
            } catch {}
            server.close(() => done());
            setTimeout(done, 500).unref();
          })
        });
      });
    });
  }
}
