import * as http from "http";
import * as crypto from "crypto";
import { SecurityScoreReport } from "../types";
import { AuditLogger } from "../core/audit-logger";

export interface DashboardServerInstance {
  server: http.Server;
  port: number;
  authToken: string;
  url: string;
  stop: () => Promise<void>;
}

function escapeHtml(str: string): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export class DashboardServer {
  public static start(
    report: SecurityScoreReport, 
    auditLogger?: AuditLogger, 
    preferredPort: number = 4173
  ): Promise<DashboardServerInstance> {
    return new Promise((resolve) => {
      const authToken = crypto.randomBytes(16).toString("hex");
      const logger = auditLogger || new AuditLogger();

      const server = http.createServer((req, res) => {
        // Security Headers
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self';");

        // Validate Host Header to prevent DNS rebinding
        const host = req.headers.host || "";
        if (!host.startsWith("127.0.0.1") && !host.startsWith("localhost")) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Forbidden: Invalid Host header" }));
          return;
        }

        const reqUrl = new URL(req.url || "/", `http://${req.headers.host}`);
        const token = reqUrl.searchParams.get("token") || req.headers["authorization"]?.replace("Bearer ", "");

        // Authentication enforcement
        if (token !== authToken) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token" }));
          return;
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

        // Render Sanitized Dashboard UI HTML
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentShield Ultimate Security Dashboard</title>
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

      server.listen(preferredPort, "127.0.0.1", () => {
        const addr = server.address();
        const port = typeof addr === "object" && addr ? addr.port : preferredPort;
        const url = `http://127.0.0.1:${port}/?token=${authToken}`;
        resolve({
          server,
          port,
          authToken,
          url,
          stop: () => new Promise<void>((res) => server.close(() => res()))
        });
      });
    });
  }
}
