
/*
 * Advanced Phishing Email Detection Platform
 * Frontend application logic.
 *
 * Authentication:
 * - JWT token stored in localStorage
 * - Bearer token sent to protected API endpoints
 * - Invalid/expired tokens are cleared automatically
 *
 * Defensive behavior:
 * - Does not visit submitted URLs
 * - Does not execute attachments
 * - Escapes dynamic HTML before rendering
 */

"use strict";


/* =========================================================
   GLOBAL STATE
   ========================================================= */

let token = localStorage.getItem("phish_token") || "";
let currentRole = localStorage.getItem("phish_role") || "";
let currentUser = localStorage.getItem("phish_user") || "";


/* =========================================================
   DOM HELPERS
   ========================================================= */

function getElement(id) {
    return document.getElementById(id);
}


function getValue(id) {
    const element = getElement(id);

    if (!element) {
        return "";
    }

    return element.value.trim();
}


/* =========================================================
   API HELPERS
   ========================================================= */

function authHeaders() {
    const headers = {
        "Content-Type": "application/json"
    };

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    return headers;
}


function bearerHeaders() {
    const headers = {};

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    return headers;
}


async function parseResponse(response) {
    try {
        return await response.json();
    } catch (error) {
        return {
            detail: "The server returned an invalid response."
        };
    }
}


function handleUnauthorized() {
    token = "";
    currentRole = "";
    currentUser = "";

    localStorage.removeItem("phish_token");
    localStorage.removeItem("phish_role");
    localStorage.removeItem("phish_user");

    const app = getElement("app");
    const auth = getElement("auth");
    const authMessage = getElement("authMessage");

    if (app) {
        app.hidden = true;
    }

    if (auth) {
        auth.hidden = false;
    }

    if (authMessage) {
        authMessage.textContent =
            "Your session has expired. Please log in again.";
    }
}


/* =========================================================
   AUTHENTICATION UI
   ========================================================= */

function showLogin() {
    const auth = getElement("auth");
    const app = getElement("app");

    if (auth) {
        auth.hidden = false;
    }

    if (app) {
        app.hidden = true;
    }
}


function showApp() {
    const auth = getElement("auth");
    const app = getElement("app");
    const session = getElement("session");
    const auditCard = getElement("auditCard");

    if (!token) {
        showLogin();
        return;
    }

    if (auth) {
        auth.hidden = true;
    }

    if (app) {
        app.hidden = false;
    }

    if (session) {
        session.textContent =
            `Signed in as ${currentUser} (${currentRole})`;
    }

    /*
     * Only administrators should see the audit section.
     */
    if (auditCard) {
        auditCard.hidden = currentRole !== "admin";
    }

    loadStats();
    loadHistory();

    if (currentRole === "admin") {
        loadAudit();
    }
}


/* =========================================================
   LOGIN
   ========================================================= */

async function login() {
    const username = getValue("username");
    const password = getValue("password");
    const authMessage = getElement("authMessage");

    if (!username || !password) {
        if (authMessage) {
            authMessage.textContent =
                "Enter both username and password.";
        }

        return;
    }

    if (authMessage) {
        authMessage.textContent = "Signing in...";
    }

    try {
        const response = await fetch(
            "/api/auth/login",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            }
        );

        const data = await parseResponse(response);

        if (!response.ok) {
            if (authMessage) {
                authMessage.textContent =
                    data.detail || "Login failed.";
            }

            return;
        }

        if (!data.access_token) {
            if (authMessage) {
                authMessage.textContent =
                    "Login succeeded but no access token was returned.";
            }

            return;
        }

        /*
         * Store the JWT returned by FastAPI.
         */
        token = data.access_token;
        currentRole = data.role || "analyst";
        currentUser = data.username || username;

        localStorage.setItem(
            "phish_token",
            token
        );

        localStorage.setItem(
            "phish_role",
            currentRole
        );

        localStorage.setItem(
            "phish_user",
            currentUser
        );

        if (authMessage) {
            authMessage.textContent = "";
        }

        showApp();

    } catch (error) {
        console.error("Login error:", error);

        if (authMessage) {
            authMessage.textContent =
                "Unable to connect to the server.";
        }
    }
}


/* =========================================================
   REGISTER
   ========================================================= */

async function registerUser() {
    const username = getValue("username");
    const password = getValue("password");
    const authMessage = getElement("authMessage");

    if (!username || !password) {
        if (authMessage) {
            authMessage.textContent =
                "Enter a username and password first.";
        }

        return;
    }

    if (authMessage) {
        authMessage.textContent =
            "Creating user...";
    }

    try {
        const response = await fetch(
            "/api/auth/register",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            }
        );

        const data = await parseResponse(response);

        if (!response.ok) {
            if (authMessage) {
                authMessage.textContent =
                    data.detail || "Registration failed.";
            }

            return;
        }

        if (authMessage) {
            authMessage.textContent =
                "User created successfully. Log in now.";
        }

    } catch (error) {
        console.error("Registration error:", error);

        if (authMessage) {
            authMessage.textContent =
                "Unable to connect to the server.";
        }
    }
}


/* =========================================================
   LOGOUT
   ========================================================= */

function logout() {
    token = "";
    currentRole = "";
    currentUser = "";

    localStorage.removeItem("phish_token");
    localStorage.removeItem("phish_role");
    localStorage.removeItem("phish_user");

    location.reload();
}


/* =========================================================
   EMAIL ANALYSIS
   ========================================================= */

async function analyzeEmail() {
    if (!token) {
        handleUnauthorized();
        return;
    }

    const payload = {
        sender: getValue("sender"),
        display_name: getValue("displayName"),
        reply_to: getValue("replyTo"),
        auth_results: getValue("authResults"),
        subject: getValue("subject"),
        body: getValue("body"),
        attachment_name: getValue("attachment")
    };

    const result = getElement("result");

    if (result) {
        result.innerHTML =
            "<p>Analyzing email...</p>";
    }

    try {
        const response = await fetch(
            "/api/analyze",
            {
                method: "POST",
                headers: authHeaders(),
                body: JSON.stringify(payload)
            }
        );

        const data = await parseResponse(response);

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        renderResult(
            response,
            data
        );

    } catch (error) {
        console.error(
            "Email analysis error:",
            error
        );

        if (result) {
            result.innerHTML =
                '<p class="error">Unable to connect to the analysis server.</p>';
        }
    }
}


/* =========================================================
   EML ANALYSIS
   ========================================================= */

async function analyzeEml() {
    if (!token) {
        handleUnauthorized();
        return;
    }

    const fileInput = getElement("emlFile");
    const result = getElement("result");

    if (!fileInput || !fileInput.files.length) {
        alert("Choose a .eml file first.");
        return;
    }

    const file = fileInput.files[0];

    if (file.size > 2 * 1024 * 1024) {
        if (result) {
            result.innerHTML =
                '<p class="error">The .eml file exceeds the 2 MB safety limit.</p>';
        }

        return;
    }

    const form = new FormData();

    form.append(
        "file",
        file
    );

    if (result) {
        result.innerHTML =
            "<p>Analyzing .eml file...</p>";
    }

    try {
        const response = await fetch(
            "/api/analyze/eml",
            {
                method: "POST",
                headers: bearerHeaders(),
                body: form
            }
        );

        const data = await parseResponse(response);

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        renderResult(
            response,
            data
        );

    } catch (error) {
        console.error(
            "EML analysis error:",
            error
        );

        if (result) {
            result.innerHTML =
                '<p class="error">Unable to connect to the analysis server.</p>';
        }
    }
}


/* =========================================================
   RENDER ANALYSIS RESULT
   ========================================================= */

function renderResult(
    response,
    data
) {
    const result = getElement("result");

    if (!result) {
        return;
    }

    if (!response.ok) {
        result.innerHTML =
            `<p class="error">${escapeHtml(
                data.detail || "Request failed."
            )}</p>`;

        return;
    }

    const indicators = (
        data.indicators || []
    )
        .map(
            item => `
                <div class="finding">
                    <b>${escapeHtml(item.type)}</b>
                    [${escapeHtml(item.severity)}]:
                    ${escapeHtml(item.description)}
                </div>
            `
        )
        .join("");

    const urls = (
        data.url_analysis || []
    )
        .map(
            item => `
                <div class="finding">
                    <b>${escapeHtml(item.url)}</b>
                    — ${escapeHtml(item.risk_score)}/100
                    <br>
                    ${(item.findings || [])
                        .map(
                            finding =>
                                escapeHtml(finding)
                        )
                        .join("<br>")}
                </div>
            `
        )
        .join("");

    const mlProbability =
        data.ml_probability == null
            ? "Unavailable — train the model first."
            : `${(
                Number(data.ml_probability) * 100
            ).toFixed(1)}%`;

    const reasons = (
        data.reasons || []
    )
        .map(
            reason =>
                `<div class="finding">✓ ${escapeHtml(reason)}</div>`
        )
        .join("");

    const recommendations = (
        data.recommendations || []
    )
        .map(
            recommendation =>
                `<li>${escapeHtml(recommendation)}</li>`
        )
        .join("");

    result.innerHTML = `
        <div class="result">

            <h2>
                ${escapeHtml(data.risk_score)}/100 —
                ${escapeHtml(data.classification)}
            </h2>

            <p>
                <b>Rule score:</b>
                ${escapeHtml(data.rule_score)}

                &nbsp;&nbsp;

                <b>ML probability:</b>
                ${escapeHtml(mlProbability)}
            </p>

            <h3>Reasons</h3>

            ${
                reasons ||
                "<p>No specific reasons recorded.</p>"
            }

            <h3>Indicators</h3>

            ${
                indicators ||
                "<p>None detected.</p>"
            }

            <h3>URLs</h3>

            ${
                urls ||
                "<p>No URLs found.</p>"
            }

            <h3>Recommendations</h3>

            ${
                recommendations
                    ? `<ul>${recommendations}</ul>`
                    : "<p>No recommendations.</p>"
            }

        </div>
    `;

    /*
     * Refresh dashboard information after
     * every successful analysis.
     */
    loadStats();
    loadHistory();

    if (currentRole === "admin") {
        loadAudit();
    }
}


/* =========================================================
   DASHBOARD STATISTICS
   ========================================================= */

async function loadStats() {
    if (!token) {
        return;
    }

    try {
        const response = await fetch(
            "/api/dashboard/stats",
            {
                method: "GET",
                headers: authHeaders()
            }
        );

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        if (!response.ok) {
            console.error(
                "Dashboard request failed:",
                response.status
            );

            return;
        }

        const data =
            await parseResponse(response);

        const total = getElement("total");
        const average = getElement("average");
        const phishing = getElement("phishing");
        const suspicious = getElement("suspicious");
        const indicators = getElement("indicators");
        const trend = getElement("trend");

        if (total) {
            total.textContent =
                data.total ?? 0;
        }

        if (average) {
            average.textContent =
                data.average_risk ?? 0;
        }

        if (phishing) {
            phishing.textContent =
                data.high_risk ?? 0;
        }

        if (suspicious) {
            suspicious.textContent =
                data.classifications?.SUSPICIOUS ?? 0;
        }

        if (indicators) {
            indicators.innerHTML = (
                data.top_indicators || []
            )
                .map(
                    item => `
                        <div class="finding">
                            ${escapeHtml(item.type)}:
                            ${escapeHtml(item.count)}
                        </div>
                    `
                )
                .join("");

            if (!indicators.innerHTML) {
                indicators.innerHTML =
                    "<p>No history.</p>";
            }
        }

        if (trend) {
            trend.innerHTML = (
                data.trend || []
            )
                .map(
                    item => {
                        const risk = Math.min(
                            100,
                            Math.max(
                                0,
                                Number(
                                    item.avg_risk || 0
                                )
                            )
                        );

                        return `
                            <div class="bar">
                                <span>
                                    ${escapeHtml(item.day)}
                                </span>

                                <i
                                    style="width:${risk}%"
                                ></i>

                                <b>
                                    ${escapeHtml(item.avg_risk)}
                                </b>
                            </div>
                        `;
                    }
                )
                .join("");

            if (!trend.innerHTML) {
                trend.innerHTML =
                    "No trend data.";
            }
        }

    } catch (error) {
        console.error(
            "Dashboard statistics error:",
            error
        );
    }
}


/* =========================================================
   ANALYSIS HISTORY
   ========================================================= */

async function loadHistory() {
    if (!token) {
        return;
    }

    try {
        const response = await fetch(
            "/api/analyses",
            {
                method: "GET",
                headers: authHeaders()
            }
        );

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        if (!response.ok) {
            console.error(
                "History request failed:",
                response.status
            );

            return;
        }

        const data =
            await parseResponse(response);

        const history =
            getElement("history");

        if (!history) {
            return;
        }

        if (!Array.isArray(data) || data.length === 0) {
            history.innerHTML =
                "<p>No analyses yet.</p>";

            return;
        }

        history.innerHTML = `
            <table>
                <tr>
                    <th>ID</th>
                    <th>User</th>
                    <th>Domain</th>
                    <th>Subject</th>
                    <th>Risk</th>
                    <th>ML</th>
                    <th>Class</th>
                </tr>

                ${data
                    .map(
                        item => `
                            <tr>
                                <td>
                                    ${escapeHtml(
                                        item.analysis_id
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.username
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.sender_domain
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.subject
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.risk_score
                                    )}
                                </td>

                                <td>
                                    ${
                                        item.ml_probability == null
                                            ? "-"
                                            : (
                                                Number(
                                                    item.ml_probability
                                                ) * 100
                                            ).toFixed(0) + "%"
                                    }
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.classification
                                    )}
                                </td>
                            </tr>
                        `
                    )
                    .join("")}
            </table>
        `;

    } catch (error) {
        console.error(
            "History error:",
            error
        );
    }
}


/* =========================================================
   ADMIN AUDIT LOG
   ========================================================= */

async function loadAudit() {
    if (!token || currentRole !== "admin") {
        return;
    }

    try {
        const response = await fetch(
            "/api/audit",
            {
                method: "GET",
                headers: authHeaders()
            }
        );

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        const data =
            await parseResponse(response);

        const audit =
            getElement("audit");

        if (!audit) {
            return;
        }

        if (!response.ok) {
            audit.innerHTML =
                `<p>${escapeHtml(
                    data.detail || "Forbidden"
                )}</p>`;

            return;
        }

        if (!Array.isArray(data) || data.length === 0) {
            audit.innerHTML =
                "<p>No audit events yet.</p>";

            return;
        }

        audit.innerHTML = `
            <table>
                <tr>
                    <th>User</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Time</th>
                </tr>

                ${data
                    .map(
                        item => `
                            <tr>
                                <td>
                                    ${escapeHtml(
                                        item.username
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.action
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.target
                                    )}
                                </td>

                                <td>
                                    ${escapeHtml(
                                        item.created_at
                                    )}
                                </td>
                            </tr>
                        `
                    )
                    .join("")}
            </table>
        `;

    } catch (error) {
        console.error(
            "Audit log error:",
            error
        );
    }
}


/* =========================================================
   HTML ESCAPING
   ========================================================= */

function escapeHtml(value) {
    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {
        /*
         * Only show the protected application when
         * a token exists.
         */
        if (token) {
            showApp();
        } else {
            showLogin();
        }
    }
);

