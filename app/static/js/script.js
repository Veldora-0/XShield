document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("#analysis-form");

    if (!form) {
        return;
    }

    form.addEventListener("submit", () => {
        const button = form.querySelector("button[type='submit']");

        if (button) {
            button.disabled = true;
            button.setAttribute("aria-busy", "true");
            button.firstChild.textContent = "Submitting...";
        }
    });
});
