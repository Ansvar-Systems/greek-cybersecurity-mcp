#!/usr/bin/env node

/**
 * Greek Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying NCSA (National Cyber Security Authority
 * of Greece) guidelines, technical reports, security advisories, and
 * cybersecurity frameworks. Published primarily in English.
 *
 * Tool prefix: gr_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
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

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "greek-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "gr_cyber_search_guidance",
    description:
      "Full-text search across NCSA (National Cyber Security Authority of Greece) guidelines and technical reports. Covers NIS2 implementation guidance, critical infrastructure protection, sector-specific cybersecurity recommendations, and GDPR technical measures. Published primarily in English.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query in English (e.g., 'NIS2 requirements', 'critical infrastructure', 'incident reporting', 'network security')",
        },
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
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
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
        reference: {
          type: "string",
          description: "NCSA document reference",
        },
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
        query: {
          type: "string",
          description: "Search query in English (e.g., 'critical vulnerability', 'ransomware', 'supply chain attack')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "gr_cyber_get_advisory",
    description:
      "Get a specific NCSA security advisory by reference (e.g., 'NCSA-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSA advisory reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "gr_cyber_list_frameworks",
    description:
      "List all NCSA frameworks and guidance series covered in this MCP, including the Greek national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "gr_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

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

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

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
        return textContent({ results, count: results.length });
      }

      case "gr_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
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
        });
      }

      case "gr_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "gr_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
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
        });
      }

      case "gr_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
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

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
