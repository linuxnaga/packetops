// Browser smoke test for the acceptance path: sign in, upload a capture, inspect packets and flows,
// run console commands, read findings, complete a training mission and generate a report.
//
//   PKO_WEB_URL=http://localhost:5173 PKO_E2E_PCAP=/path/to/real.pcapng node e2e/smoke.mjs
//
// Requires a running API with seeded dev users (PKO_AUTH_MODE=dev) and Playwright's Chromium.
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// CommonJS resolution so a globally installed Playwright is found as well as a local one.
const { chromium } = createRequire(import.meta.url)("playwright");
const here = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.PKO_WEB_URL ?? "http://localhost:5173";
const PCAP = process.env.PKO_E2E_PCAP ?? path.resolve(here, "../../backend/fixtures/training/tcp-handshake.pcapng");
const USER = process.env.PKO_E2E_USER ?? "analyst@acme.example";
const SHOTS = process.env.PKO_E2E_SHOTS;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

const step = (name) => console.log(`• ${name}`);
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: false }); };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const consoleErrors = [];
if (process.env.PKO_E2E_DEBUG) page.on("response", async (r) => { if (r.url().includes("/missions/")) console.log("  ", r.request().method(), r.url().replace(BASE, ""), r.status(), (await r.text().catch(() => "")).slice(0, 300)); });
page.on("pageerror", (e) => consoleErrors.push(String(e)));
// CSP violations and failed script loads surface only as console errors.
page.on("console", (m) => { if (m.type() === "error" && /Content Security Policy|Refused to/.test(m.text())) consoleErrors.push(m.text()); });
const api = async (method, p, body) => page.evaluate(async ([m, url, b]) => {
  const r = await fetch(`/api/v1${url}`, { method: m, headers: { Authorization: `Bearer ${localStorage.getItem("packetops.token")}`, ...(b ? { "Content-Type": "application/json" } : {}) }, body: b ? JSON.stringify(b) : undefined });
  return r.status === 204 ? null : r.json();
}, [method, p, body]);

try {
  step("sign in");
  await page.goto(BASE);
  await page.getByLabel("User").fill(USER);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("heading", { name: "Investigation overview" }).waitFor();
  await shot(page, "01-overview");

  step(`upload ${path.basename(PCAP)}`);
  await page.getByRole("link", { name: "PCAP Workbench" }).click();
  await page.locator('input[type="file"]').setInputFiles(PCAP);
  await page.getByRole("button", { name: "Upload and analyse" }).click();
  await page.locator("text=/●\\s*analyzed/").first().waitFor({ timeout: 120_000 });
  const captureId = await page.evaluate(() => localStorage.getItem("packetops.capture"));
  if (!captureId) throw new Error("no capture selected after upload");

  step("inspect packets");
  const rows = page.locator("table.tbl tbody tr");
  await rows.first().waitFor();
  const n = await rows.count();
  if (n < 1) throw new Error("packet table is empty");
  await rows.first().click();
  await page.getByRole("heading", { name: /Frame #1/ }).waitFor();
  await page.getByLabel("Display filter").fill("tcp.flags.reset == 1");
  await page.getByRole("button", { name: "Apply" }).click();
  await page.waitForTimeout(800);
  await shot(page, "02-workbench");

  step("flows");
  await page.getByRole("link", { name: "Flow Explorer" }).click();
  await page.getByRole("heading", { name: /Flow Explorer/ }).waitFor();
  await page.waitForTimeout(800);
  await shot(page, "03-flows");

  step("findings");
  await page.getByRole("link", { name: "Findings", exact: true }).click();
  await page.waitForTimeout(1200);
  const findings = await api("GET", `/captures/${captureId}/findings`);
  console.log(`  ${findings.total ?? findings.items?.length} finding(s): ${(findings.items ?? []).map((f) => f.rule_id).join(", ")}`);
  await shot(page, "04-findings");

  step("Command Deck");
  await page.getByRole("link", { name: "Command Deck" }).click();
  const input = page.getByLabel("Console command");
  for (const cmd of ["pcap inspect", "tcp handshakes", "findings list"]) {
    await input.fill(cmd);
    await input.press("Enter");
    await page.locator(`[role=log] >> text=${cmd}`).last().waitFor();
    await page.waitForTimeout(400);
  }
  const log = await page.locator("[role=log]").innerText();
  if (/Unknown command|Internal error/.test(log)) throw new Error(`console error:\n${log}`);
  await input.fill("tcp hand");
  await input.press("Tab");
  await page.waitForFunction(() => document.querySelector('[aria-label="Console command"]')?.value.trim() === "tcp handshakes", null, { timeout: 5000 })
    .catch(() => { throw new Error("tab completion did not complete 'tcp hand'"); });
  await input.fill("");
  await shot(page, "05-console");

  step("training mission: tcp-handshake");
  await page.getByRole("link", { name: "Training" }).click();
  const card = page.locator("div.rounded-md", { has: page.getByRole("heading", { name: "TCP handshake failure" }) });
  await page.waitForLoadState("networkidle");
  const startBtn = card.getByRole("button");
  if (await startBtn.isEnabled()) await startBtn.click(); // disabled when this mission is already the active one
  await page.getByText("Active mission: TCP handshake failure").waitFor({ timeout: 60_000 });
  // Answers are read from the mission capture's findings, the same evidence a learner uses.
  const run = await api("GET", "/missions/active");
  for (let i = 0; i < 40; i++) {
    const c = await api("GET", `/captures/${run.capture_id}`);
    if (c.status === "analyzed") break;
    await page.waitForTimeout(500);
  }
  const mf = (await api("GET", `/captures/${run.capture_id}/findings`)).items;
  const t001 = mf.find((f) => f.rule_id === "TCP-001");
  const t002 = await api("GET", `/findings/${mf.find((f) => f.rule_id === "TCP-002").id}`);
  const answers = [t001.subject_key, String((await api("GET", `/findings/${t001.id}`)).metrics.syn_segments), String(t002.packets.find((p) => /RST/i.test(p.role)).frame)];
  await page.reload();
  for (let i = 0; i < answers.length; i++) {
    const box = page.getByLabel(`Answer for objective ${i + 1}`);
    await box.fill(answers[i]);
    await box.press("Enter");
    await page.waitForTimeout(600);
  }
  await page.getByText(/Mission complete/).waitFor({ timeout: 15_000 });
  await shot(page, "06-missions");

  step("report");
  await page.evaluate((id) => localStorage.setItem("packetops.capture", id), captureId);
  await page.goto(`${BASE}/reports`);
  await page.getByRole("button", { name: "Generate" }).click();
  await page.getByText(/Created packetops-report-/).waitFor({ timeout: 60_000 });
  await shot(page, "07-reports");

  step("BIG-IP and help screens render");
  await page.getByRole("link", { name: "BIG-IP" }).click();
  await page.getByRole("heading", { name: "BIG-IP intelligence" }).waitFor();
  await shot(page, "08-bigip");
  await page.getByRole("link", { name: "Rules & help" }).click();
  await page.getByText(/Detection rules \(\d+\)/).waitFor();

  step("dark theme");
  await page.getByRole("button", { name: "Toggle colour theme" }).click();
  await page.getByRole("link", { name: "Command Deck" }).click();
  await shot(page, "09-console-dark");

  if (consoleErrors.length) throw new Error(`page errors:\n${consoleErrors.join("\n")}`);
  console.log("E2E smoke passed");
} catch (e) {
  await shot(page, "zz-failure").catch(() => undefined);
  console.error(`E2E smoke FAILED: ${e.message}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
