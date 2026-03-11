/**
 * Backend server for the FakeLink Detector web application.
 *
 * This server:
 * - Serves the static frontend files (HTML, CSS, JS).
 * - Exposes an API endpoint that accepts a URL.
 * - Applies simple heuristic rules to determine whether the URL
 *   looks safe or suspicious / phishing.
 */

const express = require("express");
const path = require("path");

// Create an Express application instance
const app = express();

// The port the server will listen on (defaults to 3000 if not provided)
const PORT = process.env.PORT || 3000;

// Built-in middleware that lets Express parse incoming JSON bodies
app.use(express.json());

// Serve all static files (index.html, style.css, script.js) from this directory
app.use(express.static(__dirname));

/**
 * Helper that attempts to safely parse a URL string and normalize it.
 * If the user omits the protocol (e.g. "example.com"), we temporarily
 * add "http://" so the URL constructor can parse it.
 *
 * @param {string} rawUrl - URL string from the user input.
 * @returns {{ url: URL | null, normalized: string | null }} Parsed URL object and normalized string.
 */
function tryParseUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
        return { url: null, normalized: null };
    }

    let working = rawUrl.trim();

    // If the URL has no protocol at all, prepend "http://"
    if (!/^https?:\/\//i.test(working)) {
        working = "http://" + working;
    }

    try {
        const parsed = new URL(working);
        return { url: parsed, normalized: parsed.href };
    } catch {
        return { url: null, normalized: null };
    }
}

/**
 * Analyze the given URL using very simple heuristic rules.
 * These rules are NOT exhaustive and are only meant as a demo.
 *
 * Rules:
 * - Mark as suspicious if URL path contains sensitive keywords.
 * - Mark as suspicious if domain has many digits or odd characters.
 * - Mark as suspicious if the URL uses plain HTTP instead of HTTPS.
 *
 * @param {string} inputUrl - The raw URL string from the user.
 * @returns {{ status: "safe" | "suspicious"; summary: string; reasons: string[] }}
 */
function analyzeUrl(inputUrl) {
    const reasons = [];

    // Simple risk score so multiple "small" signals can add up.
    // We use this to avoid missing phishing links that look clean on a single rule.
    let riskScore = 0;

    const { url, normalized } = tryParseUrl(inputUrl);

    if (!url) {
        // If we cannot parse the URL at all, treat it as suspicious
        return {
            status: "suspicious",
            summary: "The URL could not be parsed and may not be valid.",
            reasons: ["The string provided does not look like a valid URL."],
            score: 10,
        };
    }

    const hostname = url.hostname || "";
    const pathname = (url.pathname || "") + (url.search || "");
    const fullUrl = normalized || inputUrl;

    // 1) Check for common phishing-related keywords in the path or query
    const suspiciousKeywords = ["login", "verify", "secure", "update", "password", "account", "bank"];
    const lowerPath = pathname.toLowerCase();

    const hitKeywords = suspiciousKeywords.filter((kw) => lowerPath.includes(kw));
    if (hitKeywords.length > 0) {
        riskScore += 2;
        reasons.push(
            `The URL path or query contains sensitive keywords: ${hitKeywords.join(", ")}. Attackers often use these to trick users into entering credentials.`
        );
    }

    // 2) Check if the domain looks unusual (many digits, weird characters, long length)
    const justDomain = hostname.toLowerCase();

    // Count digits in the domain
    const digitCount = (justDomain.match(/\d/g) || []).length;

    // Count non-alphanumeric characters, excluding dots and hyphens
    const specialCharCount = (justDomain.match(/[^a-z0-9\.\-]/g) || []).length;

    // Very long domains can be used to hide the true brand name
    const tooLongDomain = justDomain.length > 30;

    if (digitCount >= 5) {
        riskScore += 2;
        reasons.push("The domain contains many numbers, which is often used by fake or throwaway domains.");
    }

    if (specialCharCount > 0) {
        riskScore += 2;
        reasons.push("The domain includes unusual characters that are uncommon in legitimate websites.");
    }

    if (tooLongDomain) {
        riskScore += 1;
        reasons.push("The domain name is very long, which can be used to obscure the real brand name.");
    }

    // 3) Check if the URL uses HTTP instead of HTTPS
    if (url.protocol.toLowerCase() === "http:") {
        riskScore += 2;
        reasons.push("The link does not use HTTPS. Legitimate sites almost always use HTTPS for security.");
    }

    // 4) Check for URL shorteners (often used to hide the final destination)
    const knownShorteners = new Set([
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "rb.gy",
        "lnkd.in",
    ]);
    if (knownShorteners.has(justDomain)) {
        riskScore += 2;
        reasons.push("The link uses a URL shortener, which can hide the real destination.");
    }

    // 5) Check if the host is an IP address (common for low-effort phishing kits)
    const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(justDomain);
    if (isIpv4) {
        riskScore += 3;
        reasons.push("The link uses a raw IP address instead of a domain name, which is uncommon for legitimate sites.");
    }

    // 6) Check for many subdomains or many hyphens (can be used to impersonate brands)
    const dotParts = justDomain.split(".").filter(Boolean);
    const subdomainCount = Math.max(0, dotParts.length - 2); // rough estimate: foo.bar.example.com => 2 subdomains
    if (subdomainCount >= 3) {
        riskScore += 2;
        reasons.push("The domain has many subdomains, which can be used to disguise the true site name.");
    }

    const hyphenCount = (justDomain.match(/\-/g) || []).length;
    if (hyphenCount >= 4) {
        riskScore += 1;
        reasons.push("The domain contains many hyphens, which is common in look‑alike phishing domains.");
    }

    // 7) Check for punycode (xn--) which can indicate look‑alike Unicode domains
    if (justDomain.includes("xn--")) {
        riskScore += 3;
        reasons.push("The domain uses punycode (xn--), which can be used for look‑alike Unicode phishing domains.");
    }

    // 8) Check for userinfo tricks: https://user:pass@real-domain.com (or just @ in URL)
    // Browsers may show the part before @ and confuse users.
    if (url.username || url.password || fullUrl.includes("@")) {
        riskScore += 3;
        reasons.push("The URL contains an '@' (userinfo) section, a common trick to mislead users about the real destination.");
    }

    // 9) Check for suspicious TLDs (not definitive, but a mild signal in combination with others)
    const tld = dotParts.length > 0 ? dotParts[dotParts.length - 1] : "";
    const higherRiskTlds = new Set(["zip", "mov", "top", "xyz", "click", "link", "rest", "country", "stream", "gq", "tk", "ml", "cf"]);
    if (tld && higherRiskTlds.has(tld)) {
        riskScore += 1;
        reasons.push(`The domain uses a higher-risk TLD (.${tld}), which is more commonly abused for phishing/spam.`);
    }

    // Decide overall status.
    // Thresholds:
    // - score >= 3 => suspicious (multiple mild signals or one strong signal)
    // - score < 3 and no reasons => safe
    // - score < 3 but with reasons => suspicious (edge cases)
    const isSuspicious = riskScore >= 3 || reasons.length > 0;

    if (!isSuspicious) {
        return {
            status: "safe",
            summary: "No obvious phishing indicators were found, but you should still stay cautious.",
            reasons: [
                "The domain and path do not match the simple phishing patterns this tool checks for.",
                "This does not guarantee the site is safe. Always check the sender, spelling, and URL carefully.",
            ],
            score: riskScore,
        };
    }

    return {
        status: "suspicious",
        summary:
            "This link triggered one or more basic phishing indicators. Do not enter passwords or sensitive data unless you fully trust the source.",
        reasons,
        score: riskScore,
    };
}

/**
 * POST /api/check-link
 *
 * Request body:
 *   { "url": "https://example.com/login" }
 *
 * Response body:
 *   {
 *      "status": "safe" | "suspicious",
 *      "summary": "Short explanation",
 *      "reasons": ["Detailed reason 1", "Detailed reason 2"]
 *   }
 */
app.post("/api/check-link", (req, res) => {
    const { url } = req.body || {};

    if (!url || typeof url !== "string") {
        return res.status(400).json({
            status: "suspicious",
            summary: "No URL was provided in the request body.",
            reasons: ["Please send a JSON object with a 'url' field containing the link to analyze."],
        });
    }

    const result = analyzeUrl(url);
    return res.json(result);
});

// Fallback route to send the main HTML file for any unknown GET routes
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Start the HTTP server and log the URL for convenience
app.listen(PORT, () => {
    console.log(`FakeLink Detector server is running at http://localhost:${PORT}`);
});

// Export the app and helper for potential testing or extension later
module.exports = { app, analyzeUrl };

