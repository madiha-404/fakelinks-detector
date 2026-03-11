/**
 * Frontend logic for the FakeLink Detector web application.
 * This version runs entirely in the browser using simple heuristics
 * instead of calling a backend API.
 */

// Grab references to the key DOM elements we need to interact with
const form = document.getElementById("link-form");
const urlInput = document.getElementById("url-input");
const checkButton = document.getElementById("check-button");
const spinner = document.getElementById("button-spinner");

const resultBox = document.getElementById("result");
const resultTitle = document.getElementById("result-title");
const resultMessage = document.getElementById("result-message");
const resultReasons = document.getElementById("result-reasons");

/**
 * Basic heuristic analysis for a URL.
 * Returns an object compatible with showResult().
 *
 * @param {string} rawUrl
 * @returns {{ status: 'safe' | 'suspicious', summary: string, reasons: string[] }}
 */
function analyzeUrl(rawUrl) {
    const reasons = [];
    let score = 0;

    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch (_) {
        return {
            status: "suspicious",
            summary: "The URL format looks invalid.",
            reasons: ["The link could not be parsed as a valid URL. Make sure it starts with http:// or https://"],
        };
    }

    const hostname = parsed.hostname.toLowerCase();
    const full = parsed.toString().toLowerCase();
    const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();

    // 1) Protocol check
    if (parsed.protocol !== "https:") {
        score += 1;
        reasons.push("The link is not using HTTPS. Secure sites should normally start with https://");
    }

    // 2) Very long URL
    if (full.length > 120) {
        score += 1;
        reasons.push("The URL is unusually long, which can be used to hide malicious parts.");
    }

    // 3) IP address instead of domain
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 2;
        reasons.push("The URL uses a raw IP address instead of a normal domain name.");
    }

    // 4) Suspicious TLDs
    const suspiciousTlds = [".ru", ".su", ".top", ".xyz", ".tk", ".pw", ".club", ".info", ".cn"];
    if (suspiciousTlds.some((tld) => hostname.endsWith(tld))) {
        score += 1;
        reasons.push("The domain ends with a top-level domain that is often abused in phishing campaigns.");
    }

    // 5) Lots of digits / hyphens in the domain
    const digitCount = (hostname.match(/\d/g) || []).length;
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (digitCount + hyphenCount >= 4) {
        score += 1;
        reasons.push("The domain contains many numbers or hyphens, which is common in fake look‑alike sites.");
    }

    // 6) Common phishing keywords
    const phishingKeywords = ["login", "signin", "verify", "update", "secure", "account", "billing", "pay", "password"];
    const keywordHits = phishingKeywords.filter((kw) => pathAndQuery.includes(kw));
    if (keywordHits.length > 0) {
        score += 1;
        reasons.push(`The link path contains sensitive keywords (${keywordHits.join(", ")}), often used in phishing pages.`);
    }

    // 7) @ symbol in the URL (can hide the real destination)
    if (full.includes("@")) {
        score += 2;
        reasons.push("The URL contains an '@' symbol, which can be used to hide the true destination.");
    }

    // 8) Mismatch between apparent brand name and domain
    const knownBrands = ["google", "facebook", "paypal", "microsoft", "netflix", "amazon", "apple", "bankofamerica"];
    const brandHits = knownBrands.filter((brand) => full.includes(brand));
    if (brandHits.length > 0 && !brandHits.some((brand) => hostname.includes(brand))) {
        score += 2;
        reasons.push("The link mentions a well‑known brand in the text or path, but the domain itself does not match that brand.");
    }

    const isSuspicious = score >= 2 || reasons.length > 0;

    if (isSuspicious) {
        return {
            status: "suspicious",
            summary: "This link looks suspicious based on several heuristic checks.",
            reasons,
        };
    }

    return {
        status: "safe",
        summary: "No obvious phishing patterns were detected, but you should still be cautious.",
        reasons: [],
    };
}

/**
 * Helper function that toggles the loading state of the button.
 * While loading:
 * - The button is disabled to prevent duplicate submissions.
 * - The text remains visible.
 * - A small spinner appears next to the text.
 *
 * @param {boolean} isLoading - Whether we are currently waiting for a response.
 */
function setLoading(isLoading) {
    checkButton.disabled = isLoading;

    if (isLoading) {
        spinner.classList.add("visible");
    } else {
        spinner.classList.remove("visible");
    }
}

/**
 * Helper function that resets and updates the result box based on the
 * result returned from the backend.
 *
 * @param {Object} data - The result payload returned by the backend API.
 * @param {string} data.status - Either "safe" or "suspicious".
 * @param {string} data.summary - Short message summarizing the result.
 * @param {string[]} data.reasons - List of detailed reasons for the decision.
 */
function showResult(data) {
    // Remove any previous "safe" / "suspicious" styling
    resultBox.classList.remove("result-safe", "result-suspicious", "hidden");

    // Apply the correct styling based on the returned status
    if (data.status === "safe") {
        resultTitle.textContent = "Safe Link";
        resultBox.classList.add("result-safe");
    } else {
        resultTitle.textContent = "Suspicious / Phishing Link";
        resultBox.classList.add("result-suspicious");
    }

    // Set the short explanation text
    resultMessage.textContent = data.summary || "";

    // Clear any previously displayed reasons
    resultReasons.innerHTML = "";

    // Add each reason as a list item for more detail
    if (Array.isArray(data.reasons) && data.reasons.length > 0) {
        for (const reason of data.reasons) {
            const li = document.createElement("li");
            li.textContent = reason;
            resultReasons.appendChild(li);
        }
    }
}

/**
 * Helper function to show an error message in the result box
 * if something goes wrong (network error, server error, etc.).
 *
 * @param {string} message - The error message to display to the user.
 */
function showError(message) {
    resultBox.classList.remove("result-safe", "result-suspicious", "hidden");
    resultBox.classList.add("result-suspicious");

    resultTitle.textContent = "Error";
    resultMessage.textContent = message;
    resultReasons.innerHTML = "";
}

/**
 * Event listener for the form submission.
 * We intercept the submit event, prevent the page from reloading,
 * and run our local heuristic checks instead of calling a backend API.
 */
form.addEventListener("submit", (event) => {
    event.preventDefault(); // Stop the browser from doing a traditional form POST

    const url = urlInput.value.trim();

    // If the user somehow submits an empty URL, simply show an error
    if (!url) {
        showError("Please paste a URL before checking.");
        return;
    }

    // Activate loading state while we talk to the backend
    setLoading(true);

    try {
        // Run local analysis in the browser
        const data = analyzeUrl(url);
        showResult(data);
    } catch (error) {
        console.error("Error analyzing link:", error);
        showError("Something went wrong while analyzing the link.");
    } finally {
        // Always turn off the loading state when the request is complete
        setLoading(false);
    }
});

