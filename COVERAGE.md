# Data Coverage

This MCP server provides access to content published by the **National Cyber Security Authority of Greece (NCSA)** at [ncsa.gov.gr](https://ncsa.gov.gr/).

## Guidance Documents

| Series | Description | Status |
|--------|-------------|--------|
| NCSA   | National cybersecurity guidelines and technical reports | Current |
| NIS2   | NIS2 Directive implementation guidance for Greece | Current |
| GDPR   | GDPR technical and organisational measures guidance | Current |

### Document types

- `technical_guideline` — Technical guidelines and implementation specifications
- `sector_guide` — Sector-specific cybersecurity guidance (energy, health, finance, transport)
- `standard` — National or harmonised standards references
- `recommendation` — Best-practice recommendations and advisories

## Security Advisories

NCSA publishes security advisories covering:

- Critical infrastructure vulnerabilities
- Sector-specific threat alerts
- CVE-referenced vulnerability notifications
- Incident response guidance

## Frameworks

The following cybersecurity frameworks are referenced in this MCP:

| ID   | Name | Description |
|------|------|-------------|
| NCSA | Greek National Cybersecurity Strategy | Official national strategy documents |
| NIS2 | NIS2 Compliance Framework | EU Directive 2022/2555 implementation in Greece |
| GDPR | GDPR Technical Measures | Data protection technical requirements |

## Language

Content is published **primarily in English**. Some older documents may be in Greek only; these are excluded from this MCP unless an English translation is available.

## Data Freshness

Data is ingested from the NCSA website on a weekly schedule (Sundays at 02:00 UTC). The `DATA_AGE` environment variable records the date of the last ingest baked into the Docker image.

To check current data freshness, call the `gr_cyber_check_data_freshness` tool.

## Not Covered

- EU-level ENISA publications (use a dedicated ENISA MCP)
- Greek legislative texts (use a dedicated Greek law MCP)
- Vendor-specific security advisories (CVE database)
