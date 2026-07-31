import puppeteer from "puppeteer-core";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = "C:\\Users\\Andrii\\.gemini\\antigravity\\brain\\e29116b4-d5ec-44e0-8891-4f993306309a";

async function main() {
    console.log(">> Launching Edge headless browser...");
    const browser = await puppeteer.launch({
        executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        headless: "new",
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-web-security", // Allows local asset testing
        ]
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 900 });

    const consoleLogs = [];
    const networkResponses = [];
    const networkErrors = [];

    // Capture console output
    page.on("console", (msg) => {
        const text = `[Browser Console ${msg.type().toUpperCase()}] ${msg.text()}`;
        consoleLogs.push(text);
        console.log(text);
    });

    // Capture page errors (e.g. unhandled exceptions, WASM panic)
    page.on("pageerror", (err) => {
        const text = `[Browser PageError] ${err.toString()}`;
        consoleLogs.push(text);
        console.error(text);
    });

    // Monitor network responses & MIME types
    page.on("response", (response) => {
        const url = response.url();
        const status = response.status();
        const contentType = response.headers()["content-type"] || "none";
        networkResponses.push({ url, status, contentType });
        if (url.includes(".wasm") || url.includes(".zkey") || url.includes("circuit")) {
            console.log(`[Network Response] ${status} ${contentType} -> ${url}`);
        }
    });

    page.on("requestfailed", (request) => {
        const text = `[Network Error] ${request.url()} -> ${request.failure()?.errorText}`;
        networkErrors.push(text);
        console.error(text);
    });

    console.log(">> Navigating to http://127.0.0.1:8080/ ...");
    await page.goto("http://127.0.0.1:8080/", { waitUntil: "networkidle0", timeout: 30000 });

    // Give Leptos SPA & WASM bundle a brief moment to finish mounting
    await new Promise((r) => setTimeout(r, 2000));

    // Check window variables
    const cryptoReady = await page.evaluate(() => window.__VICHE_CRYPTO_READY__);
    const cryptoError = await page.evaluate(() => window.__VICHE_CRYPTO_ERROR__);
    const snarkjsLoaded = await page.evaluate(() => Boolean(window.snarkjs?.groth16));
    const poseidonLoaded = await page.evaluate(() => Boolean(window.__VICHE_POSEIDON__));

    console.log("=================================================");
    console.log(" Browser Environment Verification Status:");
    console.log("   __VICHE_CRYPTO_READY__ :", cryptoReady);
    console.log("   __VICHE_CRYPTO_ERROR__ :", cryptoError ?? "None");
    console.log("   snarkjs.groth16 loaded :", snarkjsLoaded);
    console.log("   Poseidon WASM loaded   :", poseidonLoaded);
    console.log("=================================================");

    const initialScreenshotPath = path.join(ARTIFACTS_DIR, "initial_page.png");
    await page.screenshot({ path: initialScreenshotPath });
    console.log(`Saved screenshot: ${initialScreenshotPath}`);

    // Inspect DOM elements
    const pageTitle = await page.title();
    const bodyHTML = await page.evaluate(() => document.body.innerHTML);
    console.log(`Page Title: ${pageTitle}`);
    console.log(`Body HTML Length: ${bodyHTML.length} characters`);

    // Look for interactive buttons (e.g. Generate Secret, Create Poll, Cast Vote)
    const buttons = await page.evaluate(() => {
        return Array.from(document.querySelectorAll("button, a.btn, input[type='submit']")).map((b) => ({
            text: b.innerText || b.value,
            id: b.id,
            className: b.className
        }));
    });
    console.log("Interactive buttons found on page:", buttons);

    // If there's an interactive button, click it
    const clickTarget = await page.$("button, a.btn");
    if (clickTarget) {
        console.log(">> Clicking first interactive element...");
        await clickTarget.click();
        await new Promise((r) => setTimeout(r, 1000));
    }

    const interactiveScreenshotPath = path.join(ARTIFACTS_DIR, "interactive_flow.png");
    await page.screenshot({ path: interactiveScreenshotPath });
    console.log(`Saved interactive screenshot: ${interactiveScreenshotPath}`);

    await browser.close();
    console.log(">> Browser agent testing finished cleanly.");
}

main().catch((err) => {
    console.error("Browser Test Error:", err);
    process.exit(1);
});
