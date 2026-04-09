#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";
import { buildCitation } from "./utils/citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "greek-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Metadata helpers --------------------------------------------------------

const DATA_AGE = process.env["DATA_AGE"] ?? "2025-01-01";

function responseMeta() {
  return {
    disclaimer:
      "Data sourced from NCSA Greece (https://ncsa.gov.gr/). Not legal advice. Verify against official sources.",
    data_age: DATA_AGE,
    copyright: "© NCSA Greece",
    source_url: "https://ncsa.gov.gr/",
  };
}

// --- Tool definitions (shared with index.ts) ---------------------------------

const TOOLS = [
  {
    name: "gr_cyber_search_guidance",
    description:
      "Full-text search across NCSA (National Cyber Security Authority of Greece) guidelines and technical reports. Covers NIS2 implementation guidance, critical infrastructure protection, sector-specific cybersecurity recommendations, and GDPR technical measures. Published primarily in English.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query in English (e.g., 'NIS2 requirements', 'critical infrastructure', 'incident reporting', 'network security')" },
        type: {
          type: "string",
          enum: ["technical_guideline", "sector_guide", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["NCSA", "NIS2", "GDPR"],
          description: "Filter by guidance series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "gr_cyber_get_guidance",
    description:
      "Get a specific NCSA guidance document by reference (e.g., 'NCSA-2023-01', 'NCSA-Guide-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "NCSA document reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "gr_cyber_search_advisories",
    description:
      "Search NCSA security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query in English (e.g., 'critical vulnerability', 'ransomware', 'supply chain attack')" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "gr_cyber_get_advisory",
    description: "Get a specific NCSA security advisory by reference (e.g., 'NCSA-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "NCSA advisory reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "gr_cyber_list_frameworks",
    description:
      "List all NCSA frameworks and guidance series covered in this MCP, including the Greek national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "gr_cyber_list_sources",
    description:
      "List all data sources used by this MCP server, including source URLs, coverage, and data freshness information.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "gr_cyber_check_data_freshness",
    description:
      "Check the freshness of the data in this MCP server. Returns the data age, last update date, and record counts for guidance and advisories.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "gr_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "sector_guide", "standard", "recommendation"]).optional(),
  series: z.enum(["NCSA", "NIS2", "GDPR"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- MCP server factory ------------------------------------------------------

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: pkgVersion },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    function textContent(data: unknown) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }

    function errorContent(message: string) {
      return {
        content: [{ type: "text" as const, text: message }],
        isError: true as const,
      };
    }

    try {
      switch (name) {
        case "gr_cyber_search_guidance": {
          const parsed = SearchGuidanceArgs.parse(args);
          const results = searchGuidance({
            query: parsed.query,
            type: parsed.type,
            series: parsed.series,
            status: parsed.status,
            limit: parsed.limit,
          });
          return textContent({ results, count: results.length, _meta: responseMeta() });
        }

        case "gr_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return textContent({
              error: `Guidance document not found: ${parsed.reference}`,
              _meta: responseMeta(),
              _error_type: "not_found",
            });
          }
          const d = doc as Record<string, unknown>;
          return textContent({
            ...doc,
            _citation: buildCitation(
              String(d.reference ?? parsed.reference),
              String(d.title ?? d.reference ?? parsed.reference),
              "gr_cyber_get_guidance",
              { reference: parsed.reference },
              d.url as string | undefined,
            ),
            _meta: responseMeta(),
          });
        }

        case "gr_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          return textContent({ results, count: results.length, _meta: responseMeta() });
        }

        case "gr_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return textContent({
              error: `Advisory not found: ${parsed.reference}`,
              _meta: responseMeta(),
              _error_type: "not_found",
            });
          }
          const a = advisory as Record<string, unknown>;
          return textContent({
            ...advisory,
            _citation: buildCitation(
              String(a.reference ?? parsed.reference),
              String(a.title ?? a.reference ?? parsed.reference),
              "gr_cyber_get_advisory",
              { reference: parsed.reference },
              a.url as string | undefined,
            ),
            _meta: responseMeta(),
          });
        }

        case "gr_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({ frameworks, count: frameworks.length, _meta: responseMeta() });
        }

        case "gr_cyber_list_sources": {
          return textContent({
            sources: [
              {
                name: "NCSA Greece",
                url: "https://ncsa.gov.gr/",
                description: "National Cyber Security Authority of Greece — official guidelines, technical reports, NIS2 implementation materials, and security advisories.",
                types: ["guidance", "advisories", "frameworks"],
                language: "primarily English",
                coverage: "Greek national cybersecurity strategy, NIS2 compliance, critical infrastructure protection, sector-specific recommendations",
              },
            ],
            _meta: responseMeta(),
          });
        }

        case "gr_cyber_check_data_freshness": {
          return textContent({
            data_age: DATA_AGE,
            source: "NCSA Greece (https://ncsa.gov.gr/)",
            note: "Run the ingest script (npm run ingest) to refresh data from the NCSA website.",
            _meta: responseMeta(),
          });
        }

        case "gr_cyber_about": {
          return textContent({
            name: SERVER_NAME,
            version: pkgVersion,
            description:
              "NCSA (National Cyber Security Authority of Greece) MCP server. Provides access to Greek national cybersecurity guidelines, technical reports, NIS2 implementation materials, critical infrastructure protection guidance, and security advisories. Content primarily in English.",
            data_source: "NCSA Greece (https://ncsa.gov.gr/)",
            coverage: {
              guidance: "National cybersecurity guidelines, NIS2 implementation guidance, critical infrastructure protection, sector-specific recommendations",
              advisories: "NCSA security advisories and vulnerability alerts",
              frameworks: "Greek national cybersecurity strategy, NIS2 compliance framework",
            },
            tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
            _meta: responseMeta(),
          });
        }

        default:
          return errorContent(`Unknown tool: ${name}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorContent(`Error executing ${name}: ${message}`);
    }
  });

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
