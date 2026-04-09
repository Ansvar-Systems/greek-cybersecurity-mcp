# Tools Reference

This MCP server exposes the following tools under the `gr_cyber_` prefix.

---

## gr_cyber_search_guidance

Full-text search across NCSA guidelines and technical reports.

**Arguments**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | Yes | Search query in English |
| `type` | enum | No | Filter by document type: `technical_guideline`, `sector_guide`, `standard`, `recommendation` |
| `series` | enum | No | Filter by series: `NCSA`, `NIS2`, `GDPR` |
| `status` | enum | No | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | No | Max results (default 20, max 100) |

**Returns** `{ results: Guidance[], count: number, _meta: ResponseMeta }`

---

## gr_cyber_get_guidance

Get a specific NCSA guidance document by reference.

**Arguments**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | Yes | NCSA document reference (e.g., `NCSA-2023-01`) |

**Returns** `Guidance & { _citation: CitationMetadata, _meta: ResponseMeta }`

---

## gr_cyber_search_advisories

Search NCSA security advisories and alerts.

**Arguments**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | Yes | Search query in English |
| `severity` | enum | No | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | No | Max results (default 20, max 100) |

**Returns** `{ results: Advisory[], count: number, _meta: ResponseMeta }`

---

## gr_cyber_get_advisory

Get a specific NCSA security advisory by reference.

**Arguments**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | Yes | NCSA advisory reference (e.g., `NCSA-2024-001`) |

**Returns** `Advisory & { _citation: CitationMetadata, _meta: ResponseMeta }`

---

## gr_cyber_list_frameworks

List all NCSA frameworks and guidance series covered in this MCP.

**Arguments** — none

**Returns** `{ frameworks: Framework[], count: number, _meta: ResponseMeta }`

---

## gr_cyber_list_sources

List all data sources used by this MCP server.

**Arguments** — none

**Returns** `{ sources: Source[], _meta: ResponseMeta }`

---

## gr_cyber_check_data_freshness

Check the freshness of the data in this MCP server.

**Arguments** — none

**Returns** `{ data_age: string, source: string, note: string, _meta: ResponseMeta }`

---

## gr_cyber_about

Return metadata about this MCP server.

**Arguments** — none

**Returns** `{ name, version, description, data_source, coverage, tools, _meta: ResponseMeta }`

---

## Common Response Fields

### `_meta` (ResponseMeta)

Present on all successful tool responses.

```json
{
  "disclaimer": "Data sourced from NCSA Greece (https://ncsa.gov.gr/). Not legal advice. Verify against official sources.",
  "data_age": "2025-01-01",
  "copyright": "© NCSA Greece",
  "source_url": "https://ncsa.gov.gr/"
}
```

### `_citation` (CitationMetadata)

Present on `gr_cyber_get_guidance` and `gr_cyber_get_advisory` responses.

```json
{
  "canonical_ref": "NCSA-2024-001",
  "display_text": "NCSA-2024-001",
  "source_url": "https://ncsa.gov.gr/...",
  "lookup": {
    "tool": "gr_cyber_get_advisory",
    "args": { "reference": "NCSA-2024-001" }
  }
}
```

### Not-found errors

When a document is not found, the tool returns a structured error (not an MCP protocol error):

```json
{
  "error": "Guidance document not found: NCSA-XXXX",
  "_meta": { ... },
  "_error_type": "not_found"
}
```
