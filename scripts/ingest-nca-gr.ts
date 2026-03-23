/**
 * Greek NCA / NCSA Ingestion Crawler
 *
 * Scrapes the National Cyber Security Authority (NCSA) of Greece website
 * (cyber.gov.gr) and populates the SQLite database with real guidance
 * documents, security advisories, and frameworks.
 *
 * Data sources:
 *   1. Alerts (cyber.gov.gr/alerts/)             — CVE bulletins, PDF-linked advisories
 *   2. Announcements (category/anakoinoseis/)     — paginated news/advisories
 *   3. Press releases (category/deltia-typou/)    — paginated press releases (→ guidance)
 *   4. Threat guidance (antimetopisi-apeilon/)    — static guidance pages (→ guidance)
 *   5. NIS2 section (odigia-nis2/)                — NIS2 implementation materials (→ guidance)
 *   6. Legislation (nomothesia/)                  — Greek cybersecurity law references (→ guidance)
 *
 * Content language: Greek (original), English titles where available.
 *
 * Usage:
 *   npx tsx scripts/ingest-nca-gr.ts                   # full crawl
 *   npx tsx scripts/ingest-nca-gr.ts --resume          # resume from last checkpoint
 *   npx tsx scripts/ingest-nca-gr.ts --dry-run         # log what would be inserted
 *   npx tsx scripts/ingest-nca-gr.ts --force           # drop and recreate DB first
 *   npx tsx scripts/ingest-nca-gr.ts --advisories-only # only crawl advisories
 *   npx tsx scripts/ingest-nca-gr.ts --guidance-only   # only crawl guidance
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["NCSA_DB_PATH"] ?? "data/ncsa.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");
const BASE_URL = "https://cyber.gov.gr";

// Category listing pages (WordPress-style paginated archives)
const ANNOUNCEMENTS_LISTING = `${BASE_URL}/category/anakoinoseis/`;
const PRESS_RELEASES_LISTING = `${BASE_URL}/category/deltia-typou/`;
const ALERTS_PAGE = `${BASE_URL}/alerts/`;

// Static guidance sections (non-paginated, link collections)
const THREAT_GUIDANCE_PAGE = `${BASE_URL}/antimetopisi-apeilon/`;
const NIS2_PAGE = `${BASE_URL}/odigia-nis2/`;
const LEGISLATION_PAGE = `${BASE_URL}/nomothesia/elliniki-nomothesia-gia-tin-kyvernoasfaleia/`;

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "AnsvarNCSACrawler/1.0 (+https://ansvar.eu; compliance research)";

// CLI flags
const cliArgs = process.argv.slice(2);
const force = cliArgs.includes("--force");
const dryRun = cliArgs.includes("--dry-run");
const resume = cliArgs.includes("--resume");
const advisoriesOnly = cliArgs.includes("--advisories-only");
const guidanceOnly = cliArgs.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_announcement_urls: string[];
  completed_press_urls: string[];
  completed_alert_urls: string[];
  completed_guidance_urls: string[];
  completed_nis2_urls: string[];
  completed_legislation_urls: string[];
  last_updated: string;
}

interface ListingEntry {
  url: string;
  title: string;
  dateBrief: string;
  summary: string;
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

const counters = {
  advisories_inserted: 0,
  advisories_skipped: 0,
  guidance_inserted: 0,
  guidance_skipped: 0,
  pages_fetched: 0,
  errors: 0,
};

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
          "Accept-Language": "el,en;q=0.9",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  counters.pages_fetched++;
  return resp.text();
}

// ---------------------------------------------------------------------------
// Greek date parsing
// ---------------------------------------------------------------------------

/**
 * Greek month names to numeric month (01-12).
 */
const EL_MONTHS: Record<string, string> = {
  // Full names
  "ιανουαρίου": "01",
  "φεβρουαρίου": "02",
  "μαρτίου": "03",
  "απριλίου": "04",
  "μαΐου": "05",
  "μαίου": "05",
  "ιουνίου": "06",
  "ιουλίου": "07",
  "αυγούστου": "08",
  "σεπτεμβρίου": "09",
  "οκτωβρίου": "10",
  "νοεμβρίου": "11",
  "δεκεμβρίου": "12",
  // Nominative
  "ιανουάριος": "01",
  "φεβρουάριος": "02",
  "μάρτιος": "03",
  "απρίλιος": "04",
  "μάιος": "05",
  "ιούνιος": "06",
  "ιούλιος": "07",
  "αύγουστος": "08",
  "σεπτέμβριος": "09",
  "οκτώβριος": "10",
  "νοέμβριος": "11",
  "δεκέμβριος": "12",
  // Abbreviated
  "ιαν": "01",
  "φεβ": "02",
  "μαρ": "03",
  "απρ": "04",
  "μαι": "05",
  "ιουν": "06",
  "ιουλ": "07",
  "αυγ": "08",
  "σεπ": "09",
  "οκτ": "10",
  "νοε": "11",
  "δεκ": "12",
};

/**
 * English month names to numeric month (01-12), for English-language
 * pages on the site.
 */
const EN_MONTHS: Record<string, string> = {
  january: "01", february: "02", march: "03", april: "04",
  may: "05", june: "06", july: "07", august: "08",
  september: "09", october: "10", november: "11", december: "12",
  jan: "01", feb: "02", mar: "03", apr: "04",
  jun: "06", jul: "07", aug: "08", sep: "09",
  oct: "10", nov: "11", dec: "12",
};

/**
 * Parse a Greek or English date string into ISO format (YYYY-MM-DD).
 * Handles:
 *   - "15 Μαρτίου 2025" / "15 Μαρτίου, 2025"
 *   - "15/03/2025" or "15.03.2025"
 *   - "2025-03-15"
 *   - "March 15, 2025"
 *   - RFC 2822 dates
 */
function parseDate(dateStr: string): string | null {
  if (!dateStr) return null;
  const s = dateStr.trim();

  // ISO format: "2025-03-15"
  const isoMatch = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (isoMatch) {
    return `${isoMatch[1]}-${isoMatch[2]!.padStart(2, "0")}-${isoMatch[3]!.padStart(2, "0")}`;
  }

  // Numeric: "15/03/2025" or "15.03.2025"
  const numericMatch = s.match(/^(\d{1,2})[./](\d{1,2})[./](\d{4})/);
  if (numericMatch) {
    const day = numericMatch[1]!.padStart(2, "0");
    const month = numericMatch[2]!.padStart(2, "0");
    const year = numericMatch[3]!;
    return `${year}-${month}-${day}`;
  }

  // Greek long: "15 Μαρτίου 2025" or "15 Μαρτίου, 2025"
  const elLongMatch = s.match(/(\d{1,2})\s+(\S+?)(?:,?\s+)(\d{4})/);
  if (elLongMatch) {
    const day = elLongMatch[1]!.padStart(2, "0");
    const monthName = elLongMatch[2]!.toLowerCase();
    const year = elLongMatch[3]!;
    const month = EL_MONTHS[monthName] ?? EN_MONTHS[monthName];
    if (month) {
      return `${year}-${month}-${day}`;
    }
  }

  // English long: "March 15, 2025"
  const enLongMatch = s.match(/(\w+)\s+(\d{1,2}),?\s+(\d{4})/);
  if (enLongMatch) {
    const monthName = enLongMatch[1]!.toLowerCase();
    const day = enLongMatch[2]!.padStart(2, "0");
    const year = enLongMatch[3]!;
    const month = EN_MONTHS[monthName];
    if (month) {
      return `${year}-${month}-${day}`;
    }
  }

  // Fallback: try RFC 2822 / ISO parsing via Date constructor
  try {
    const d = new Date(s);
    if (!isNaN(d.getTime())) {
      return d.toISOString().slice(0, 10);
    }
  } catch {
    // Ignore
  }

  return null;
}

// ---------------------------------------------------------------------------
// HTML parsing helpers
// ---------------------------------------------------------------------------

/**
 * Extract CVE references from text. Returns JSON array string or null.
 */
function extractCves(text: string): string | null {
  const cves = new Set<string>();
  const re = /CVE-\d{4}-\d{4,}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    cves.add(m[0]);
  }
  return cves.size > 0 ? JSON.stringify(Array.from(cves).sort()) : null;
}

/**
 * Infer severity from page text using CVSS scores and severity keywords
 * in both Greek and English.
 */
function inferSeverity(text: string): string | null {
  // Explicit CVSS score
  const cvssMatch = text.match(
    /CVSS(?:\s+(?:Base\s+)?Score)?[:\s]+(\d+(?:\.\d+)?)/i,
  );
  if (cvssMatch) {
    const score = parseFloat(cvssMatch[1]!);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  const lower = text.toLowerCase();

  // Greek severity keywords
  if (
    lower.includes("κρίσιμη") ||
    lower.includes("κρίσιμο") ||
    lower.includes("κρίσιμης") ||
    lower.includes("critical")
  ) {
    return "critical";
  }
  if (
    lower.includes("υψηλή") ||
    lower.includes("υψηλό") ||
    lower.includes("υψηλής") ||
    lower.includes("σοβαρή") ||
    lower.includes("σοβαρό") ||
    lower.includes("high")
  ) {
    return "high";
  }
  if (
    lower.includes("μέτρια") ||
    lower.includes("μέτριο") ||
    lower.includes("medium") ||
    lower.includes("moderate")
  ) {
    return "medium";
  }
  if (lower.includes("χαμηλή") || lower.includes("χαμηλό") || lower.includes("low")) {
    return "low";
  }

  return null;
}

/**
 * Extract topics from title and body text as a JSON array string.
 * Matches both Greek and English keywords.
 */
function extractTopics(title: string, text: string): string {
  const topics: string[] = [];
  const lower = (title + " " + text).toLowerCase();

  const topicMap: Record<string, string> = {
    // Greek keywords
    "κυβερνοασφάλεια": "cybersecurity",
    "κυβερνοεπίθεση": "cyberattack",
    "κυβερνοεπιθέσεις": "cyberattack",
    "λυτρισμικό": "ransomware",
    "λυτρισμικών": "ransomware",
    "ηλεκτρονικό ψάρεμα": "phishing",
    "ηλεκτρονικής απάτης": "fraud",
    "ηλεκτρονικών απατών": "fraud",
    "κρίσιμη υποδομή": "critical infrastructure",
    "κρίσιμες υποδομές": "critical infrastructure",
    "προσωπικά δεδομένα": "data protection",
    "αυθεντικοποίηση": "authentication",
    "ταυτοποίηση": "authentication",
    "κρυπτογραφία": "cryptography",
    "ευπάθεια": "vulnerability",
    "ευπάθειες": "vulnerability",
    "αναφορά συμβάντων": "incident reporting",
    "συμβάν": "incident",
    "εφοδιαστική αλυσίδα": "supply chain",
    "nis2": "NIS2",
    "nis-2": "NIS2",
    "5160/2024": "Law 5160/2024",
    "5086/2024": "Law 5086/2024",
    "δημόσιος τομέας": "public sector",
    "υγεία": "healthcare",
    "ενέργεια": "energy",
    "τραπεζικός": "banking",
    "τηλεπικοινωνίες": "telecommunications",
    "μεταφορές": "transport",
    // English keywords
    ransomware: "ransomware",
    phishing: "phishing",
    malware: "malware",
    vpn: "VPN",
    firewall: "firewall",
    "remote code execution": "RCE",
    "denial of service": "DoS",
    ddos: "DDoS",
    "sql injection": "SQL injection",
    "zero-day": "zero-day",
    "0-day": "zero-day",
    "supply chain": "supply chain",
    "active directory": "Active Directory",
    "incident response": "incident response",
    "critical infrastructure": "critical infrastructure",
    scada: "SCADA",
    ics: "ICS",
    iot: "IoT",
    gdpr: "GDPR",
    "data breach": "data breach",
    "patch management": "patch management",
    // Vendor names
    cisco: "Cisco",
    microsoft: "Microsoft",
    fortinet: "Fortinet",
    ivanti: "Ivanti",
    oracle: "Oracle",
    apache: "Apache",
    linux: "Linux",
    windows: "Windows",
    android: "Android",
    apple: "Apple",
    vmware: "VMware",
  };

  for (const [keyword, topic] of Object.entries(topicMap)) {
    if (lower.includes(keyword) && !topics.includes(topic)) {
      topics.push(topic);
    }
  }

  return JSON.stringify(topics.slice(0, 10));
}

/**
 * Build a stable reference ID from a cyber.gov.gr URL.
 *
 * Examples:
 *   /enimerosi-gia-ayximeni-roi/            -> NCSA-GR-enimerosi-gia-ayximeni-roi
 *   /category/anakoinoseis/some-post/       -> NCSA-GR-A-some-post
 *   /antimetopisi-apeilon/odigos-15-sim.../ -> NCSA-GR-G-odigos-15-sim...
 *   /alerts/ (PDF link)                     -> NCSA-GR-CVE-20250801
 */
function buildReference(url: string, prefix: string): string {
  const path = url
    .replace(BASE_URL, "")
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");

  // Remove category prefixes to get the slug
  const slug = path
    .replace(/^category\/[^/]+\//, "")
    .replace(/^antimetopisi-apeilon\//, "")
    .replace(/^odigia-nis2\//, "")
    .replace(/^nomothesia\/[^/]*\//, "")
    .replace(/^nomothesia\//, "")
    .replace(/\//g, "-");

  const ref = `NCSA-GR-${prefix}-${slug}`.slice(0, 100);
  // Clean trailing hyphens
  return ref.replace(/-+$/, "");
}

/**
 * Build a reference for a PDF alert bulletin from its URL.
 * e.g. .../uploads/2025/08/20250801_CVE.pdf -> NCSA-GR-CVE-20250801
 */
function buildPdfReference(pdfUrl: string): string {
  const filenameMatch = pdfUrl.match(/\/([^/]+)\.pdf$/i);
  if (filenameMatch) {
    const filename = filenameMatch[1]!
      .replace(/%[0-9A-F]{2}/gi, "")
      .replace(/[^a-zA-Z0-9_-]/g, "-")
      .slice(0, 60);
    return `NCSA-GR-CVE-${filename}`;
  }
  return `NCSA-GR-CVE-${Date.now()}`;
}

// ---------------------------------------------------------------------------
// Detail page scraper
// ---------------------------------------------------------------------------

interface DetailPage {
  title: string;
  date: string | null;
  sections: Record<string, string>;
  fullText: string;
  pdfLinks: string[];
}

/**
 * Scrape a single cyber.gov.gr detail page.
 * The site is WordPress-based. Content is typically in article.post or
 * .entry-content with h1/h2 headings, paragraphs, and list items.
 */
async function scrapeDetailPage(url: string): Promise<DetailPage> {
  const html = await fetchText(url);
  const $ = cheerio.load(html);

  // Title: first h1 in content area, or <title> tag
  const title =
    $("article h1, .entry-content h1, .post-title, h1.entry-title, h1")
      .first()
      .text()
      .trim() ||
    $("title")
      .text()
      .replace(/\s*[-|]\s*Εθνική Αρχή Κυβερνοασφάλειας.*$/, "")
      .trim();

  // Date: look for WordPress date elements, time tags, or structured text
  let dateStr: string | null = null;

  // Strategy 1: <time> elements with datetime attribute
  $("time[datetime]").each((_i, el) => {
    if (!dateStr) {
      const dt = $(el).attr("datetime");
      if (dt) {
        dateStr = parseDate(dt);
      }
    }
  });

  // Strategy 2: date classes common in WordPress themes
  if (!dateStr) {
    $(
      ".entry-date, .post-date, .date, .published, span.meta-date, .posted-on",
    ).each((_i, el) => {
      if (!dateStr) {
        const text = $(el).text().trim();
        dateStr = parseDate(text);
      }
    });
  }

  // Strategy 3: scan the first paragraphs for date patterns
  if (!dateStr) {
    $("article p, .entry-content p")
      .slice(0, 5)
      .each((_i, el) => {
        if (!dateStr) {
          const text = $(el).text().trim();
          // Match Greek date: "15 Μαρτίου 2025" or numeric "15/03/2025"
          const dateMatch = text.match(
            /\d{1,2}\s+\S+(?:ου|ίου)\s+\d{4}|\d{1,2}[./]\d{1,2}[./]\d{4}/,
          );
          if (dateMatch) {
            dateStr = parseDate(dateMatch[0]);
          }
        }
      });
  }

  // Extract sections by h2/h3 headings
  const sections: Record<string, string> = {};
  const contentArea = $(
    "article .entry-content, .entry-content, article, main, .content",
  ).first();

  const headings = contentArea.find("h2, h3");
  if (headings.length > 0) {
    headings.each((_i, el) => {
      const heading = $(el).text().trim();
      let sectionContent = "";
      let next = $(el).next();
      while (next.length > 0 && !next.is("h2") && !next.is("h3")) {
        sectionContent += next.text().trim() + "\n";
        next = next.next();
      }
      if (sectionContent.trim()) {
        sections[heading] = sectionContent.trim();
      }
    });
  }

  // Full text: all text from the content area, whitespace-normalised
  const fullText = contentArea.text().replace(/\s+/g, " ").trim();

  // Collect PDF links (the site publishes CVE bulletins as PDFs)
  const pdfLinks: string[] = [];
  contentArea.find('a[href$=".pdf"], a[href*=".pdf"]').each((_i, el) => {
    const href = $(el).attr("href");
    if (href) {
      const fullHref = href.startsWith("http")
        ? href
        : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;
      pdfLinks.push(fullHref);
    }
  });

  return { title, date: dateStr, sections, fullText, pdfLinks };
}

// ---------------------------------------------------------------------------
// WordPress category listing scraper
// ---------------------------------------------------------------------------

/**
 * Scrape a WordPress category listing page.
 * Returns entries and the URL of the next page (or null).
 *
 * WordPress category archives use /category/slug/page/N/ for pagination.
 * Each entry is an <article> with a title link and excerpt.
 */
async function scrapeListingPage(
  pageUrl: string,
): Promise<{ entries: ListingEntry[]; nextPageUrl: string | null }> {
  const html = await fetchText(pageUrl);
  const $ = cheerio.load(html);
  const entries: ListingEntry[] = [];
  const seen = new Set<string>();

  // Strategy 1: WordPress article elements
  $("article").each((_i, el) => {
    const $el = $(el);
    const titleLink = $el.find("h2 a, h3 a, .entry-title a").first();
    const href = titleLink.attr("href");
    if (!href || seen.has(href)) return;
    seen.add(href);

    const fullHref = href.startsWith("http")
      ? href
      : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;

    const title = titleLink.text().trim();
    const dateText =
      $el.find("time, .entry-date, .post-date, .date").first().text().trim() ??
      "";
    const excerpt =
      $el.find(".entry-summary, .entry-excerpt, .excerpt, p").first().text().trim() ??
      "";

    if (title.length > 3) {
      entries.push({
        url: fullHref,
        title,
        dateBrief: dateText,
        summary: excerpt.slice(0, 400),
      });
    }
  });

  // Strategy 2: fallback to any links pointing to detail pages within main content
  if (entries.length === 0) {
    $("main a[href], .content a[href], .site-content a[href]").each(
      (_i, el) => {
        const href = $(el).attr("href") ?? "";
        const fullHref = href.startsWith("http")
          ? href
          : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;

        // Only follow links that look like post URLs (contain year or slug pattern)
        if (
          !seen.has(fullHref) &&
          fullHref.startsWith(BASE_URL) &&
          !fullHref.includes("/category/") &&
          !fullHref.includes("/page/") &&
          !fullHref.includes("/tag/") &&
          !fullHref.endsWith("/alerts/") &&
          !fullHref.endsWith("/en/") &&
          fullHref !== `${BASE_URL}/` &&
          fullHref.length > BASE_URL.length + 5
        ) {
          const title = $(el).text().trim();
          if (title.length > 5) {
            seen.add(fullHref);
            entries.push({
              url: fullHref,
              title,
              dateBrief: "",
              summary: "",
            });
          }
        }
      },
    );
  }

  // Pagination: WordPress uses /page/N/ or ?paged=N
  let nextPageUrl: string | null = null;

  // Look for "next" pagination link (arrow or text "Επόμενη", "Next", etc.)
  $("a.next, a.page-numbers.next, .nav-next a, .pagination .next a").each(
    (_i, el) => {
      if (!nextPageUrl) {
        const href = $(el).attr("href");
        if (href) {
          nextPageUrl = href.startsWith("http")
            ? href
            : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;
        }
      }
    },
  );

  // Fallback: look for any pagination link with /page/N+1/
  if (!nextPageUrl) {
    const currentPageMatch = pageUrl.match(/\/page\/(\d+)\/?/);
    const currentPage = currentPageMatch
      ? parseInt(currentPageMatch[1]!, 10)
      : 1;
    const nextPage = currentPage + 1;

    $("a[href]").each((_i, el) => {
      if (!nextPageUrl) {
        const href = $(el).attr("href") ?? "";
        if (href.includes(`/page/${nextPage}/`) || href.includes(`/page/${nextPage}`)) {
          nextPageUrl = href.startsWith("http")
            ? href
            : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;
        }
      }
    });
  }

  return { entries, nextPageUrl };
}

/**
 * Crawl all pages of a WordPress category listing.
 */
async function crawlAllListingPages(
  startUrl: string,
  label: string,
): Promise<ListingEntry[]> {
  const allEntries: ListingEntry[] = [];
  let currentUrl: string | null = startUrl;
  let pageNum = 1;

  while (currentUrl) {
    console.log(`  [${label}] Fetching page ${pageNum}: ${currentUrl}`);
    try {
      const { entries, nextPageUrl } = await scrapeListingPage(currentUrl);
      allEntries.push(...entries);
      console.log(
        `  [${label}] Page ${pageNum}: ${entries.length} entries found`,
      );
      currentUrl = nextPageUrl;
      pageNum++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [${label}] Error on page ${pageNum}: ${msg}`);
      counters.errors++;
      break;
    }
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const unique = allEntries.filter((e) => {
    if (seen.has(e.url)) return false;
    seen.add(e.url);
    return true;
  });

  console.log(
    `  [${label}] Total: ${unique.length} unique entries across ${pageNum - 1} pages`,
  );
  return unique;
}

// ---------------------------------------------------------------------------
// Static guidance page scraper
// ---------------------------------------------------------------------------

/**
 * Scrape a static guidance hub page (e.g. /antimetopisi-apeilon/) and
 * extract links to individual guidance pages.
 */
async function scrapeGuidanceHub(
  hubUrl: string,
  label: string,
): Promise<ListingEntry[]> {
  console.log(`  [${label}] Fetching hub page: ${hubUrl}`);
  const entries: ListingEntry[] = [];
  const seen = new Set<string>();

  try {
    const html = await fetchText(hubUrl);
    const $ = cheerio.load(html);

    // Collect all internal links from the content area
    $(
      "article a[href], .entry-content a[href], main a[href], .page-content a[href]",
    ).each((_i, el) => {
      const href = $(el).attr("href") ?? "";
      const fullHref = href.startsWith("http")
        ? href
        : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;

      if (
        !seen.has(fullHref) &&
        fullHref.startsWith(BASE_URL) &&
        !fullHref.endsWith(".pdf") &&
        !fullHref.includes("/category/") &&
        !fullHref.includes("/tag/") &&
        !fullHref.includes("/page/") &&
        fullHref !== hubUrl &&
        fullHref !== `${BASE_URL}/` &&
        fullHref.length > BASE_URL.length + 5
      ) {
        seen.add(fullHref);
        const title = $(el).text().trim();
        if (title.length > 3) {
          entries.push({
            url: fullHref,
            title,
            dateBrief: "",
            summary: "",
          });
        }
      }
    });

    console.log(`  [${label}] Found ${entries.length} linked guidance pages`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [${label}] Error fetching hub: ${msg}`);
    counters.errors++;
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Alerts page scraper (PDF bulletin links)
// ---------------------------------------------------------------------------

/**
 * Scrape the /alerts/ page for PDF bulletin links. Each bulletin is a
 * CVE advisory newsletter published as a PDF.
 */
async function scrapeAlertsPage(): Promise<ListingEntry[]> {
  console.log("  [Alerts] Fetching alerts page");
  const entries: ListingEntry[] = [];
  const seen = new Set<string>();

  try {
    const html = await fetchText(ALERTS_PAGE);
    const $ = cheerio.load(html);

    // Collect all PDF links from the page — these are CVE bulletins
    $('a[href$=".pdf"], a[href*=".pdf"]').each((_i, el) => {
      const href = $(el).attr("href") ?? "";
      const fullHref = href.startsWith("http")
        ? href
        : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;

      if (!seen.has(fullHref) && fullHref.includes("CVE")) {
        seen.add(fullHref);
        const title = $(el).text().trim() || "CVE Bulletin";
        entries.push({
          url: fullHref,
          title,
          dateBrief: "",
          summary: "",
        });
      }
    });

    // Also collect links to individual alert post pages (non-PDF)
    $(
      "article a[href], .entry-content a[href], main a[href]",
    ).each((_i, el) => {
      const href = $(el).attr("href") ?? "";
      const fullHref = href.startsWith("http")
        ? href
        : `${BASE_URL}${href.startsWith("/") ? "" : "/"}${href}`;

      if (
        !seen.has(fullHref) &&
        fullHref.startsWith(BASE_URL) &&
        !fullHref.endsWith(".pdf") &&
        !fullHref.includes("/category/") &&
        !fullHref.includes("/tag/") &&
        !fullHref.includes("/page/") &&
        !fullHref.endsWith("/alerts/") &&
        fullHref !== `${BASE_URL}/` &&
        fullHref.length > BASE_URL.length + 5
      ) {
        seen.add(fullHref);
        const title = $(el).text().trim();
        if (title.length > 5) {
          entries.push({
            url: fullHref,
            title,
            dateBrief: "",
            summary: "",
          });
        }
      }
    });

    console.log(
      `  [Alerts] Found ${entries.length} items (PDF bulletins + alert pages)`,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [Alerts] Error: ${msg}`);
    counters.errors++;
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Advisory processing
// ---------------------------------------------------------------------------

/**
 * Process a PDF bulletin link as an advisory. Since we cannot parse PDFs
 * natively, we record the metadata (URL, date extracted from filename,
 * reference) with a descriptive full_text pointing to the PDF source.
 */
function processPdfBulletin(
  db: Database.Database,
  pdfUrl: string,
  progress: Progress,
): void {
  if (progress.completed_alert_urls.includes(pdfUrl)) {
    counters.advisories_skipped++;
    return;
  }

  const reference = buildPdfReference(pdfUrl);

  const existing = db
    .prepare("SELECT 1 FROM advisories WHERE reference = ?")
    .get(reference);
  if (existing) {
    counters.advisories_skipped++;
    progress.completed_alert_urls.push(pdfUrl);
    return;
  }

  // Extract date from the PDF filename (pattern: 20250801_CVE.pdf)
  const dateMatch = pdfUrl.match(/(\d{4})(\d{2})(\d{2})/);
  const date = dateMatch
    ? `${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}`
    : null;

  // Extract a title from the filename
  const filenameMatch = pdfUrl.match(/\/([^/]+)\.pdf$/i);
  const filename = filenameMatch?.[1] ?? "CVE Bulletin";
  const title = `NCSA CVE Bulletin ${date ?? filename}`;

  const fullText =
    `NCSA Greece CVE Vulnerability Bulletin.\n` +
    `Published: ${date ?? "unknown"}\n` +
    `Source: ${pdfUrl}\n\n` +
    `This bulletin from the National Cyber Security Authority of Greece ` +
    `(Εθνική Αρχή Κυβερνοασφάλειας) contains CVE vulnerability listings, ` +
    `CISA/CERT-EU alerts and advisories, and cybersecurity news. ` +
    `The full content is available as a PDF download from the source URL.`;

  const row: AdvisoryRow = {
    reference,
    title,
    date,
    severity: null,
    affected_products: null,
    summary: `NCSA Greece CVE vulnerability bulletin (${date ?? "date unknown"}). Contains CVE listings, CISA/CERT-EU advisories.`,
    full_text: fullText,
    cve_references: null,
  };

  if (dryRun) {
    console.log(
      `    [dry-run] Would insert PDF advisory: ${reference} | ${title}`,
    );
  } else {
    db.prepare(
      `INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      row.reference,
      row.title,
      row.date,
      row.severity,
      row.affected_products,
      row.summary,
      row.full_text,
      row.cve_references,
    );
  }

  counters.advisories_inserted++;
  progress.completed_alert_urls.push(pdfUrl);
}

/**
 * Process a web page as an advisory (announcements that look like alerts).
 */
async function processAdvisoryPage(
  db: Database.Database,
  url: string,
  progress: Progress,
): Promise<void> {
  if (progress.completed_announcement_urls.includes(url)) {
    counters.advisories_skipped++;
    return;
  }

  const reference = buildReference(url, "A");

  const existing = db
    .prepare("SELECT 1 FROM advisories WHERE reference = ?")
    .get(reference);
  if (existing) {
    counters.advisories_skipped++;
    progress.completed_announcement_urls.push(url);
    return;
  }

  console.log(`    Scraping advisory: ${url}`);
  let detail: DetailPage;
  try {
    detail = await scrapeDetailPage(url);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`    Error scraping ${url}: ${msg}`);
    counters.errors++;
    return;
  }

  if (!detail.fullText || detail.fullText.length < 50) {
    console.warn(`    Skipping ${url}: insufficient content`);
    counters.errors++;
    return;
  }

  const title = detail.title || reference;
  const severity = inferSeverity(detail.fullText);
  const cveRefs = extractCves(detail.fullText);

  // Build summary from first section or first 600 chars
  const sectionValues = Object.values(detail.sections);
  const summary =
    sectionValues.length > 0
      ? sectionValues[0]!.slice(0, 600)
      : detail.fullText.slice(0, 600);

  const row: AdvisoryRow = {
    reference,
    title,
    date: detail.date,
    severity,
    affected_products: null,
    summary: summary.trim(),
    full_text: detail.fullText,
    cve_references: cveRefs,
  };

  if (dryRun) {
    console.log(
      `    [dry-run] Would insert advisory: ${reference} | ${title.slice(0, 70)} | severity=${severity ?? "unknown"} | CVEs=${cveRefs ?? "none"}`,
    );
  } else {
    db.prepare(
      `INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      row.reference,
      row.title,
      row.date,
      row.severity,
      row.affected_products,
      row.summary,
      row.full_text,
      row.cve_references,
    );
  }

  counters.advisories_inserted++;
  progress.completed_announcement_urls.push(url);
}

// ---------------------------------------------------------------------------
// Guidance processing
// ---------------------------------------------------------------------------

type GuidanceSectionType =
  | "press_release"
  | "threat_guidance"
  | "nis2_guidance"
  | "legislation_reference";

function contentTypeInfo(section: GuidanceSectionType): {
  type: string;
  series: string;
} {
  switch (section) {
    case "press_release":
      return { type: "press_release", series: "NCSA-Press" };
    case "threat_guidance":
      return { type: "technical_guideline", series: "NCSA-Threat-Guidance" };
    case "nis2_guidance":
      return { type: "sector_guide", series: "NIS2" };
    case "legislation_reference":
      return { type: "standard", series: "NCSA-Legislation" };
  }
}

function refPrefix(section: GuidanceSectionType): string {
  switch (section) {
    case "press_release":
      return "P";
    case "threat_guidance":
      return "G";
    case "nis2_guidance":
      return "N";
    case "legislation_reference":
      return "L";
  }
}

async function processGuidanceEntry(
  db: Database.Database,
  url: string,
  section: GuidanceSectionType,
  completedList: string[],
): Promise<void> {
  if (completedList.includes(url)) {
    counters.guidance_skipped++;
    return;
  }

  const reference = buildReference(url, refPrefix(section));

  const existing = db
    .prepare("SELECT 1 FROM guidance WHERE reference = ?")
    .get(reference);
  if (existing) {
    counters.guidance_skipped++;
    completedList.push(url);
    return;
  }

  console.log(`    Scraping ${section}: ${url}`);
  let detail: DetailPage;
  try {
    detail = await scrapeDetailPage(url);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`    Error scraping ${url}: ${msg}`);
    counters.errors++;
    return;
  }

  if (!detail.fullText || detail.fullText.length < 50) {
    console.warn(`    Skipping ${url}: insufficient content`);
    counters.errors++;
    return;
  }

  const { type, series } = contentTypeInfo(section);
  const title = detail.title || reference;
  const topics = extractTopics(title, detail.fullText);

  // Summary: first section or first 600 chars
  const sectionValues = Object.values(detail.sections);
  const summary =
    sectionValues.length > 0
      ? sectionValues[0]!.slice(0, 600)
      : detail.fullText.slice(0, 600);

  const row: GuidanceRow = {
    reference,
    title,
    title_en: null,
    date: detail.date,
    type,
    series,
    summary: summary.trim(),
    full_text: detail.fullText,
    topics,
    status: "current",
  };

  if (dryRun) {
    console.log(
      `    [dry-run] Would insert guidance: ${reference} | ${title.slice(0, 70)} | type=${type}`,
    );
  } else {
    db.prepare(
      `INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      row.reference,
      row.title,
      row.title_en,
      row.date,
      row.type,
      row.series,
      row.summary,
      row.full_text,
      row.topics,
      row.status,
    );
  }

  counters.guidance_inserted++;
  completedList.push(url);
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_announcement_urls.length} announcements, ` +
          `${p.completed_press_urls.length} press releases, ` +
          `${p.completed_alert_urls.length} alerts, ` +
          `${p.completed_guidance_urls.length} guidance, ` +
          `${p.completed_nis2_urls.length} NIS2, ` +
          `${p.completed_legislation_urls.length} legislation`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_announcement_urls: [],
    completed_press_urls: [],
    completed_alert_urls: [],
    completed_guidance_urls: [],
    completed_nis2_urls: [],
    completed_legislation_urls: [],
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  console.log(`Database initialised at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Framework definitions (static)
// ---------------------------------------------------------------------------

const FRAMEWORKS: FrameworkRow[] = [
  {
    id: "ncsa-gr",
    name: "Εθνική Αρχή Κυβερνοασφάλειας (ΕΑΚ)",
    name_en: "National Cyber Security Authority (NCSA) of Greece",
    description:
      "The NCSA (Εθνική Αρχή Κυβερνοασφάλειας) is the competent national authority " +
      "for cybersecurity in Greece, established under Law 5086/2024. It operates under " +
      "the Ministry of Digital Governance (Υπουργείο Ψηφιακής Διακυβέρνησης) and serves " +
      "as the NIS2 competent authority, the national CSIRT coordination point, and the " +
      "ENISA liaison for Greece. Publishes cybersecurity guidelines, CVE bulletins, " +
      "threat advisories, and NIS2 implementation guidance.",
    document_count: 0,
  },
  {
    id: "nis2-gr",
    name: "NIS2 Ελλάδα — Νόμος 5160/2024",
    name_en: "NIS2 Greece — Law 5160/2024",
    description:
      "Greece transposed the NIS2 Directive (EU 2022/2555) into national law through " +
      "Law 5160/2024, published in the Official Gazette on 27 November 2024. The law " +
      "establishes cybersecurity requirements for essential and important entities, " +
      "incident reporting obligations, and supervisory arrangements under the NCSA. " +
      "The NCSA publishes implementation guidance, a scope assessment tool (test " +
      "ypagoges), and a compliance assessment framework.",
    document_count: 0,
  },
  {
    id: "ncsa-threat-guidance",
    name: "Αντιμετώπιση Απειλών — Συστάσεις NCSA",
    name_en: "Threat Response — NCSA Recommendations",
    description:
      "Threat mitigation guidance published by the NCSA covering ransomware prevention, " +
      "phishing countermeasures, cybersecurity best practices for public sector and " +
      "businesses, healthcare system security, and academic institution protection. " +
      "Includes sector-specific guidance for energy, banking, healthcare, and " +
      "telecommunications.",
    document_count: 0,
  },
  {
    id: "ncsa-cve-bulletins",
    name: "Δελτία Ευπαθειών CVE — NCSA",
    name_en: "CVE Vulnerability Bulletins — NCSA",
    description:
      "Biweekly vulnerability bulletins published by the NCSA containing CVE listings, " +
      "CISA/CERT-EU alerts and advisories, patch notifications, and cybersecurity news. " +
      "Published as PDF newsletters targeting CISOs and IT security officers of public " +
      "organisations and businesses.",
    document_count: 0,
  },
  {
    id: "gr-cyber-legislation",
    name: "Ελληνική Νομοθεσία Κυβερνοασφάλειας",
    name_en: "Greek Cybersecurity Legislation",
    description:
      "Greek national legislation on cybersecurity including Law 5160/2024 (NIS2 " +
      "transposition), Law 5086/2024 (NCSA establishment), and related regulatory " +
      "frameworks. Includes references to sector-specific regulations and " +
      "Joint Ministerial Decisions on cybersecurity requirements.",
    document_count: 0,
  },
];

function insertFrameworks(db: Database.Database): void {
  const stmt = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );
  for (const f of FRAMEWORKS) {
    stmt.run(f.id, f.name, f.name_en, f.description, f.document_count);
  }
  console.log(`Inserted ${FRAMEWORKS.length} frameworks`);
}

function updateFrameworkCounts(db: Database.Database): void {
  const advisoryCount = (
    db.prepare("SELECT COUNT(*) as n FROM advisories").get() as { n: number }
  ).n;
  const guidanceCount = (
    db.prepare("SELECT COUNT(*) as n FROM guidance").get() as { n: number }
  ).n;

  // CVE bulletins count
  const cveCount = (
    db
      .prepare(
        "SELECT COUNT(*) as n FROM advisories WHERE reference LIKE 'NCSA-GR-CVE-%'",
      )
      .get() as { n: number }
  ).n;

  // NIS2 guidance count
  const nis2Count = (
    db
      .prepare("SELECT COUNT(*) as n FROM guidance WHERE series = 'NIS2'")
      .get() as { n: number }
  ).n;

  // Threat guidance count
  const threatCount = (
    db
      .prepare(
        "SELECT COUNT(*) as n FROM guidance WHERE series = 'NCSA-Threat-Guidance'",
      )
      .get() as { n: number }
  ).n;

  // Legislation count
  const legCount = (
    db
      .prepare(
        "SELECT COUNT(*) as n FROM guidance WHERE series = 'NCSA-Legislation'",
      )
      .get() as { n: number }
  ).n;

  const update = db.prepare(
    "UPDATE frameworks SET document_count = ? WHERE id = ?",
  );
  update.run(advisoryCount + guidanceCount, "ncsa-gr");
  update.run(nis2Count, "nis2-gr");
  update.run(threatCount, "ncsa-threat-guidance");
  update.run(cveCount, "ncsa-cve-bulletins");
  update.run(legCount, "gr-cyber-legislation");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=== Greek NCA/NCSA Ingestion Crawler ===");
  console.log(`Database: ${DB_PATH}`);
  console.log(
    `Flags: force=${force} dry-run=${dryRun} resume=${resume} ` +
      `advisories-only=${advisoriesOnly} guidance-only=${guidanceOnly}`,
  );
  console.log();

  const db = initDatabase();
  const progress = loadProgress();

  // Insert framework definitions
  if (!dryRun) {
    insertFrameworks(db);
  }

  // ------------------------------------------------------------------
  // Phase 1: Crawl Alerts page (PDF bulletins + alert posts) -> advisories
  // ------------------------------------------------------------------
  if (!guidanceOnly) {
    console.log("\n--- Phase 1: Alerts (CVE Bulletins) -> advisories ---");

    const alertEntries = await scrapeAlertsPage();

    console.log(
      `\n  Total alert items: ${alertEntries.length}`,
    );

    let idx = 0;
    for (const entry of alertEntries) {
      idx++;
      if (idx % 10 === 0 || idx === 1) {
        console.log(
          `  Progress: ${idx}/${alertEntries.length} alerts (${counters.advisories_inserted} inserted, ${counters.advisories_skipped} skipped)`,
        );
      }

      if (entry.url.endsWith(".pdf") || entry.url.includes(".pdf")) {
        // PDF bulletin — record metadata
        processPdfBulletin(db, entry.url, progress);
      } else {
        // HTML alert post — scrape the page
        await processAdvisoryPage(db, entry.url, progress);
      }

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
    console.log(
      `\n  Alerts complete: ${counters.advisories_inserted} inserted, ${counters.advisories_skipped} skipped`,
    );
  }

  // ------------------------------------------------------------------
  // Phase 2: Crawl Announcements (Ανακοινώσεις) -> advisories
  // ------------------------------------------------------------------
  if (!guidanceOnly) {
    console.log(
      "\n--- Phase 2: Announcements (Ανακοινώσεις) -> advisories ---",
    );

    const entries = await crawlAllListingPages(
      ANNOUNCEMENTS_LISTING,
      "Ανακοινώσεις",
    );

    console.log(`\n  Total unique announcement URLs: ${entries.length}`);

    let idx = 0;
    for (const entry of entries) {
      idx++;
      if (idx % 10 === 0 || idx === 1) {
        console.log(
          `  Progress: ${idx}/${entries.length} announcements (${counters.advisories_inserted} inserted, ${counters.advisories_skipped} skipped)`,
        );
      }

      await processAdvisoryPage(db, entry.url, progress);

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
    console.log(
      `\n  Announcements complete: ${counters.advisories_inserted} total inserted`,
    );
  }

  // ------------------------------------------------------------------
  // Phase 3: Crawl Press Releases (Δελτία Τύπου) -> guidance
  // ------------------------------------------------------------------
  if (!advisoriesOnly) {
    console.log(
      "\n--- Phase 3: Press Releases (Δελτία Τύπου) -> guidance ---",
    );

    const entries = await crawlAllListingPages(
      PRESS_RELEASES_LISTING,
      "Δελτία-Τύπου",
    );

    console.log(`\n  Total unique press release URLs: ${entries.length}`);

    let idx = 0;
    for (const entry of entries) {
      idx++;
      if (idx % 10 === 0 || idx === 1) {
        console.log(
          `  Progress: ${idx}/${entries.length} press releases (${counters.guidance_inserted} inserted)`,
        );
      }

      await processGuidanceEntry(
        db,
        entry.url,
        "press_release",
        progress.completed_press_urls,
      );

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
  }

  // ------------------------------------------------------------------
  // Phase 4: Crawl Threat Guidance (Αντιμετώπιση Απειλών) -> guidance
  // ------------------------------------------------------------------
  if (!advisoriesOnly) {
    console.log(
      "\n--- Phase 4: Threat Guidance (Αντιμετώπιση Απειλών) -> guidance ---",
    );

    const entries = await scrapeGuidanceHub(
      THREAT_GUIDANCE_PAGE,
      "Αντιμετώπιση-Απειλών",
    );

    let idx = 0;
    for (const entry of entries) {
      idx++;
      console.log(
        `  Progress: ${idx}/${entries.length} threat guidance (${counters.guidance_inserted} inserted)`,
      );

      await processGuidanceEntry(
        db,
        entry.url,
        "threat_guidance",
        progress.completed_guidance_urls,
      );

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
  }

  // ------------------------------------------------------------------
  // Phase 5: Crawl NIS2 section (Οδηγία NIS2) -> guidance
  // ------------------------------------------------------------------
  if (!advisoriesOnly) {
    console.log("\n--- Phase 5: NIS2 (Οδηγία NIS2) -> guidance ---");

    const entries = await scrapeGuidanceHub(NIS2_PAGE, "NIS2");

    let idx = 0;
    for (const entry of entries) {
      idx++;
      console.log(
        `  Progress: ${idx}/${entries.length} NIS2 guidance (${counters.guidance_inserted} inserted)`,
      );

      await processGuidanceEntry(
        db,
        entry.url,
        "nis2_guidance",
        progress.completed_nis2_urls,
      );

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
  }

  // ------------------------------------------------------------------
  // Phase 6: Crawl Legislation (Νομοθεσία) -> guidance
  // ------------------------------------------------------------------
  if (!advisoriesOnly) {
    console.log(
      "\n--- Phase 6: Legislation (Ελληνική Νομοθεσία) -> guidance ---",
    );

    const entries = await scrapeGuidanceHub(
      LEGISLATION_PAGE,
      "Νομοθεσία",
    );

    let idx = 0;
    for (const entry of entries) {
      idx++;
      console.log(
        `  Progress: ${idx}/${entries.length} legislation (${counters.guidance_inserted} inserted)`,
      );

      await processGuidanceEntry(
        db,
        entry.url,
        "legislation_reference",
        progress.completed_legislation_urls,
      );

      if (idx % 25 === 0 && !dryRun) {
        saveProgress(progress);
      }
    }

    if (!dryRun) saveProgress(progress);
  }

  // ------------------------------------------------------------------
  // Final: update framework document counts and report
  // ------------------------------------------------------------------
  if (!dryRun) {
    updateFrameworkCounts(db);
    saveProgress(progress);
  }

  db.close();

  console.log("\n=== Ingestion Complete ===");
  console.log(`  Pages fetched:       ${counters.pages_fetched}`);
  console.log(`  Advisories inserted: ${counters.advisories_inserted}`);
  console.log(`  Advisories skipped:  ${counters.advisories_skipped}`);
  console.log(`  Guidance inserted:   ${counters.guidance_inserted}`);
  console.log(`  Guidance skipped:    ${counters.guidance_skipped}`);
  console.log(`  Errors:              ${counters.errors}`);
  if (dryRun) {
    console.log("\n  (dry-run mode -- no data was written)");
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
