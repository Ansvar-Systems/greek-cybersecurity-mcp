/**
 * Seed the NCSA database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Includes representative NCSA (National Cyber Security Authority of Greece)
 * cybersecurity guidelines, NIS2 guidance, and sample security advisories.
 * Content primarily in English.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["NCSA_DB_PATH"] ?? "data/ncsa.db";
const force = process.argv.includes("--force");

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

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "ncsa-guidelines",
    name: "NCSA Cybersecurity Guidelines",
    name_en: "NCSA Cybersecurity Guidelines",
    description: "Guidelines and technical recommendations published by the National Cyber Security Authority of Greece covering network security, incident response, NIS2 compliance, and critical infrastructure protection.",
    document_count: 31,
  },
  {
    id: "nis2-gr",
    name: "NIS2 Directive Implementation in Greece",
    name_en: "NIS2 Directive Implementation in Greece",
    description: "Guidance on the implementation of the NIS2 Directive (EU 2022/2555) in Greece, including entity categorisation, security requirements, incident notification obligations, and supervisory arrangements under NCSA.",
    document_count: 10,
  },
  {
    id: "ncsa-sector-guides",
    name: "NCSA Sector-Specific Security Guides",
    name_en: "NCSA Sector-Specific Security Guides",
    description: "Sector-specific cybersecurity guidance for energy, banking, healthcare, public administration, and telecommunications sectors in Greece.",
    document_count: 18,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);
for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "NCSA-2023-01",
    title: "Cybersecurity Risk Management Framework for Greek Organisations",
    title_en: "Cybersecurity Risk Management Framework for Greek Organisations",
    date: "2023-05-10",
    type: "technical_guideline",
    series: "NCSA",
    summary: "A comprehensive risk management framework for Greek public and private sector organisations aligned with NIS2, ISO 27001:2022, and ENISA guidelines. Covers asset identification, threat assessment, risk treatment, and continuous monitoring.",
    full_text: "This framework provides Greek organisations with a structured approach to cybersecurity risk management, aligned with the requirements of the NIS2 Directive and international standards.\n\nRisk Management Phases:\n\n1. Context Establishment:\n- Define the scope and boundaries of the risk management process\n- Identify stakeholders and their requirements\n- Establish risk acceptance criteria aligned with business objectives\n- Document applicable legal and regulatory requirements (NIS2, GDPR, sector-specific regulations)\n\n2. Risk Identification:\n- Asset inventory (information assets, IT systems, operational technology)\n- Threat identification using ENISA Threat Landscape and sector-specific threat intelligence\n- Vulnerability assessment through technical scanning and manual review\n\n3. Risk Analysis:\n- Use a qualitative or semi-quantitative approach\n- Assess likelihood and impact for each identified risk\n- Calculate risk level using a defined risk matrix (5x5 recommended)\n\n4. Risk Evaluation:\n- Compare risk levels against acceptance criteria\n- Prioritise risks requiring treatment\n\n5. Risk Treatment:\n- Risk mitigation: implement security controls (refer to ISO 27002:2022)\n- Risk transfer: cybersecurity insurance\n- Risk acceptance: document and monitor residual risks\n- Risk avoidance: discontinue the activity creating the risk\n\n6. Monitoring and Review:\n- Continuous monitoring of key risk indicators (KRIs)\n- Annual risk assessment review\n- Update risk register when significant changes occur\n\nNIS2 Alignment:\nArticle 21 of NIS2 requires essential and important entities to implement appropriate technical, operational, and organisational measures based on a risk assessment. This framework directly supports compliance with these requirements.",
    topics: JSON.stringify(["risk management", "NIS2", "ISO 27001", "threat assessment", "cybersecurity"]),
    status: "current",
  },
  {
    reference: "NCSA-2023-02",
    title: "Network Security Guidelines for Critical Infrastructure Operators",
    title_en: "Network Security Guidelines for Critical Infrastructure Operators",
    date: "2023-08-22",
    type: "technical_guideline",
    series: "NCSA",
    summary: "Technical guidelines for network security in critical infrastructure environments. Covers network segmentation, firewall configuration, intrusion detection, VPN security, and OT/IT convergence security.",
    full_text: "Critical infrastructure operators face unique network security challenges due to the convergence of operational technology (OT) and information technology (IT) systems. This guide addresses these challenges.\n\nNetwork Segmentation:\n- Implement a defence-in-depth architecture with multiple security zones\n- Separate OT networks from IT networks using industrial demilitarised zones (IDMZ)\n- Apply the principle of least privilege for all inter-zone communications\n- Document all approved data flows across zone boundaries\n\nFirewall and Perimeter Security:\n- Deploy next-generation firewalls at all zone boundaries\n- Implement application-layer filtering\n- Deny all traffic by default, allow only explicitly permitted flows\n- Regularly review and update firewall rules (at least quarterly)\n\nIntrusion Detection and Prevention:\n- Deploy IDS/IPS sensors at critical network chokepoints\n- Maintain updated threat signatures\n- Configure alerts for anomalous traffic patterns\n- Consider network traffic analysis (NTA) for OT environments\n\nVPN Security:\n- Require TLS 1.2+ for all remote access VPNs\n- Enforce MFA for all VPN connections\n- Implement split tunnelling controls to prevent traffic leakage\n- Monitor VPN access logs for anomalies\n\nOT/IT Security Convergence:\n- Apply IEC 62443 standards for industrial control systems\n- Maintain separate credentials for OT and IT environments\n- Use unidirectional gateways (data diodes) where appropriate for OT\n- Patch OT systems cautiously with vendor guidance",
    topics: JSON.stringify(["network security", "critical infrastructure", "OT security", "ICS", "firewall", "VPN"]),
    status: "current",
  },
  {
    reference: "NCSA-2022-03",
    title: "Incident Response Planning Guide for Greek Organisations",
    title_en: "Incident Response Planning Guide for Greek Organisations",
    date: "2022-11-15",
    type: "technical_guideline",
    series: "NCSA",
    summary: "A practical guide for developing and implementing a cybersecurity incident response plan compliant with NIS2 notification requirements. Covers preparation, detection, containment, eradication, recovery, and post-incident activities.",
    full_text: "Effective incident response requires preparation before incidents occur. This guide helps Greek organisations build incident response capabilities aligned with NIS2 requirements.\n\nIncident Response Plan Development:\n- Define incident severity levels and corresponding response procedures\n- Establish clear roles and responsibilities (CISO, IR team, legal, communications)\n- Create communication trees for internal and external notifications\n- Identify and pre-authorise key contacts (NCSA, law enforcement, sector regulator)\n\nNIS2 Notification Requirements:\nArticle 23 of NIS2 mandates three-tier incident notification:\n1. Early warning within 24 hours of becoming aware of a significant incident\n2. Incident notification within 72 hours with initial assessment of impact and severity\n3. Final report within one month with detailed description, root cause, and mitigation measures\n\nSignificant incidents that trigger notification include those causing or capable of causing severe operational disruption or financial losses.\n\nDetection and Triage:\n- Centralise security event logging (SIEM)\n- Define incident categories (malware, phishing, data breach, DDoS, insider threat)\n- Establish triage procedures to determine severity within 2 hours of detection\n\nContainment Strategies:\n- Short-term containment: isolate affected systems to prevent spread\n- Long-term containment: implement additional monitoring, change credentials\n- Evidence preservation: maintain chain of custody for forensic investigation\n\nPost-Incident:\n- Conduct a post-incident review within 30 days\n- Update the incident response plan based on lessons learned\n- Share anonymised indicators of compromise with NCSA",
    topics: JSON.stringify(["incident response", "NIS2", "notification", "CSIRT", "forensics", "recovery"]),
    status: "current",
  },
  {
    reference: "NCSA-NIS2-2023-01",
    title: "NIS2 Implementation Guide for Greek Entities",
    title_en: "NIS2 Implementation Guide for Greek Entities",
    date: "2023-10-17",
    type: "sector_guide",
    series: "NIS2",
    summary: "Comprehensive guide for Greek essential and important entities on implementing the NIS2 Directive. Covers entity classification, registration with NCSA, security requirements under Article 21, incident reporting under Article 23, and supervisory expectations.",
    full_text: "The NIS2 Directive (EU 2022/2555) entered into force on 16 January 2023 and must be transposed into national law by 17 October 2024.\n\nEntity Classification:\nEssential Entities: energy, transport, banking, financial market infrastructure, health, drinking water, waste water, digital infrastructure, ICT service management, public administration, space.\nImportant Entities: postal services, waste management, chemical manufacturing, food production, manufacturing, digital service providers.\n\nRegistration:\nGreek entities must register with the NCSA. The registration process requires disclosure of: legal name and registration number, sector and subsector, type of entity (essential/important), contact details for the security officer, and details of cross-border operations.\n\nSecurity Measures (Article 21):\nOrganisations must implement measures proportionate to their risk exposure:\n1. Policies for risk analysis and information system security\n2. Incident handling\n3. Business continuity (backups, disaster recovery, crisis management)\n4. Supply chain security\n5. Security in network and information systems acquisition, development, and maintenance\n6. Policies to assess the effectiveness of cybersecurity risk management measures\n7. Basic cyber hygiene practices and cybersecurity training\n8. Policies and procedures regarding the use of cryptography\n9. Human resources security, access control policies, and asset management\n10. Multi-factor authentication or continuous authentication solutions\n\nSanctions:\nEssential entities: up to EUR 10 million or 2% of global annual turnover.\nImportant entities: up to EUR 7 million or 1.4% of global annual turnover.",
    topics: JSON.stringify(["NIS2", "compliance", "Greece", "registration", "security requirements", "sanctions"]),
    status: "current",
  },
  {
    reference: "NCSA-2023-04",
    title: "Supply Chain Security Guidelines for Greek Organisations",
    title_en: "Supply Chain Security Guidelines for Greek Organisations",
    date: "2023-12-01",
    type: "technical_guideline",
    series: "NCSA",
    summary: "Guidelines for managing cybersecurity risks in the supply chain, as required by NIS2 Article 21. Covers supplier risk assessment, contractual security requirements, software supply chain security, and monitoring supplier compliance.",
    full_text: "Supply chain attacks have emerged as one of the most impactful threat vectors. High-profile incidents (SolarWinds, Kaseya) demonstrate that attackers target suppliers to reach their ultimate targets.\n\nSupplier Risk Assessment:\n- Categorise suppliers by criticality and access level to your systems and data\n- Conduct security due diligence before onboarding critical suppliers\n- Request evidence of information security certifications (ISO 27001, SOC 2)\n- Assess supplier incident response capabilities\n\nContractual Requirements:\n- Include security requirements in all supplier contracts\n- Specify incident notification obligations (aligned with NIS2 timeframes)\n- Reserve the right to audit supplier security practices\n- Define data handling and retention requirements\n- Include provisions for secure disposal of data at contract end\n\nSoftware Supply Chain:\n- Require Software Bill of Materials (SBOM) from software suppliers\n- Implement software composition analysis (SCA) in development pipelines\n- Monitor for known vulnerabilities in third-party components\n- Evaluate supplier secure development practices (SDLC)\n\nOngoing Monitoring:\n- Review supplier security posture at least annually\n- Monitor threat intelligence for supplier-related advisories\n- Maintain a supplier register with security assessment results\n- Define exit procedures for suppliers who fail security assessments",
    topics: JSON.stringify(["supply chain", "supplier security", "SBOM", "NIS2", "third-party risk"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status);
  }
});
insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "NCSA-2024-001",
    title: "Critical Vulnerability in Fortinet FortiGate VPN — CVE-2024-21762",
    date: "2024-02-09",
    severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS 7.4.0-7.4.2", "Fortinet FortiOS 7.2.0-7.2.6", "Fortinet FortiProxy"]),
    summary: "A critical out-of-bounds write vulnerability in FortiOS and FortiProxy is being actively exploited. Allows unauthenticated remote code execution on vulnerable VPN appliances.",
    full_text: "The NCSA alerts Greek organisations to the active exploitation of CVE-2024-21762 affecting Fortinet FortiGate VPN appliances. The vulnerability is an out-of-bounds write in the FortiOS/FortiProxy web management interface SSL-VPN component.\n\nCVSS v3.1 Score: 9.6 (Critical)\n\nImpact: An unauthenticated remote attacker can execute arbitrary code or commands via specially crafted HTTP requests.\n\nAffected versions: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14; FortiProxy 7.4.0-7.4.2, 7.2.0-7.2.8, 7.0.0-7.0.14.\n\nRecommended actions:\n1. Update to FortiOS 7.4.3, 7.2.7, 7.0.14, or 6.4.15 immediately\n2. If patching is not immediately possible, disable HTTPS/HTTP access to the management interface from the internet\n3. Review access logs for indicators of compromise\n4. Consult Fortinet's published IoC list for signs of prior compromise\n5. Report suspected compromises to NCSA",
    cve_references: JSON.stringify(["CVE-2024-21762"]),
  },
  {
    reference: "NCSA-2023-010",
    title: "Ransomware Targeting Greek Healthcare and Public Sector",
    date: "2023-07-20",
    severity: "high",
    affected_products: JSON.stringify(["Windows Server", "VMware vSphere", "Hospital Information Systems", "Public sector IT infrastructure"]),
    summary: "NCSA has observed a surge in ransomware attacks targeting Greek healthcare institutions and public sector organisations. Multiple groups including LockBit and Cl0p have been observed targeting Greek entities.",
    full_text: "The NCSA has observed a significant increase in ransomware attacks targeting Greek healthcare and public sector organisations in the first half of 2023.\n\nThreat Actors Observed:\n- LockBit 3.0: Double extortion ransomware with affiliate model\n- Cl0p: Primarily exploiting file transfer vulnerabilities (GoAnywhere, MOVEit)\n- BlackCat/ALPHV: Sophisticated ransomware with data exfiltration\n\nInitial Access Vectors:\n- Exploitation of unpatched vulnerabilities in internet-facing systems\n- Phishing emails with malicious attachments or links\n- Compromised Remote Desktop Protocol (RDP) credentials\n- Supply chain compromise via third-party software\n\nImpact on Healthcare:\nRansomware attacks on healthcare institutions can directly endanger patient safety by disrupting electronic health records, medical devices, and clinical systems.\n\nRecommended Preventive Measures:\n1. Maintain and test offline backups (3-2-1 rule)\n2. Implement MFA on all remote access systems, especially RDP\n3. Patch internet-facing systems within 24-48 hours of critical patches\n4. Segment networks to limit lateral movement\n5. Deploy EDR/XDR solutions with behavioural detection\n6. Conduct regular tabletop exercises simulating ransomware scenarios\n\nIncident Reporting:\nOrganisations experiencing ransomware attacks should report to NCSA immediately and preserve evidence for forensic investigation.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSA-2023-006",
    title: "Critical MOVEit Transfer Vulnerability Actively Exploited — CVE-2023-34362",
    date: "2023-06-05",
    severity: "critical",
    affected_products: JSON.stringify(["Progress MOVEit Transfer", "Progress MOVEit Cloud"]),
    summary: "A critical SQL injection vulnerability in Progress MOVEit Transfer is being exploited globally by the Cl0p ransomware group. Greek organisations using MOVEit should take immediate action.",
    full_text: "The NCSA alerts Greek organisations to the active mass exploitation of CVE-2023-34362, a critical SQL injection vulnerability in Progress MOVEit Transfer.\n\nVulnerability Details:\nThe vulnerability exists in the MOVEit Transfer web application and allows unauthenticated attackers to inject SQL commands, leading to unauthorised access to the MOVEit database and exposure of transferred files.\n\nAttribution:\nThe Cl0p ransomware group has claimed responsibility for widespread exploitation of this vulnerability. Hundreds of organisations globally have been confirmed as victims.\n\nImpact Assessment:\n- Exposure of sensitive files transferred through MOVEit\n- Potential GDPR breach notification obligations if personal data was accessed\n- Reputational and regulatory consequences for affected organisations\n\nImmediate Actions:\n1. Apply Progress Software's emergency patch immediately\n2. Block external access to MOVEit Transfer until patched\n3. Review HTTP access logs for SQL injection patterns (look for 'machine_id' in queries)\n4. Assess whether personal data was exposed (GDPR 72-hour notification to HDPA if applicable)\n5. Contact NCSA for incident response support",
    cve_references: JSON.stringify(["CVE-2023-34362"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references);
  }
});
insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
