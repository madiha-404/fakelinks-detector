/**
 * Frontend logic for the FakeLink Detector web application.
 * This file wires up the form, sends the URL to the backend API,
 * shows a loading animation while waiting, and displays the results.
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
 * and call our backend API instead.
 */
form.addEventListener("submit", async (event) => {
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
        // Send the URL to our backend analysis endpoint
        const response = await fetch("/api/check-link", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            // If the server returned an HTTP error status, show a generic error
            showError("Failed to check the link. Please try again in a moment.");
            return;
        }

        // Parse the JSON body returned from the backend
        const data = await response.json();

        // Display the result with the proper styling and explanations
        showResult(data);
    } catch (error) {
        // Network or unexpected errors are handled here
        console.error("Error calling /api/check-link:", error);
        showError("An unexpected error occurred while checking the link.");
    } finally {
        // Always turn off the loading state when the request is complete
        setLoading(false);
    }
});

