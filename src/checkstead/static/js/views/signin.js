// @ts-check
// Sign-in. Shows only the methods this server has turned on, and says why the
// others are unavailable.

import { h, icon } from "../dom.js";

/** @typedef {import("../app.js").Context} Context */

/** @param {Context} ctx */
export function renderSignIn(ctx) {
  const options = h("div", { class: "options" }, h("p", { class: "muted small" }, "Checking which sign-in methods are on…"));
  const error = h("p", { class: "error-text", role: "alert", hidden: true });
  const card = h(
    "div",
    { class: "gate-card" },
    h("span", { class: "brand" }, icon("shield"), "Checkstead"),
    h("h1", null, "Sign in"),
    h("p", { class: "muted" }, "Dependency risk with the evidence behind it. The first person to sign in becomes the administrator. After that, an administrator adds each person."),
    options,
    error,
    h("p", { class: "muted small" }, "Signing in only identifies you. Scanning repositories uses the separate Checkstead GitHub App, which reads and scans repositories once an administrator installs it."),
  );
  ctx.api.sso().then(
    (status) => {
      const buttons = [];
      if (status.github.enabled) buttons.push(h("a", { class: "btn", href: status.github.start }, icon("github"), "Sign in with GitHub"));
      if (status.entra.enabled) buttons.push(h("a", { class: "btn", href: status.entra.start }, icon("microsoft"), "Sign in with Microsoft"));
      if (status.local && status.local.enabled) {
        const local = h("button", { type: "button", class: "btn primary" }, icon("computer"), "Sign in on this computer");
        local.addEventListener("click", async () => {
          local.setAttribute("disabled", "");
          error.hidden = true;
          try {
            await ctx.api.signInLocal();
            await ctx.signedIn();
          } catch (failure) {
            error.textContent = /** @type {Error} */ (failure).message;
            error.hidden = false;
            local.removeAttribute("disabled");
          }
        });
        buttons.push(local);
      }
      if (status["azure-devops"] && status["azure-devops"].enabled) buttons.push(azureDevOpsForm(ctx, error));
      if (!buttons.length) {
        options.replaceChildren(h("p", { class: "muted" }, "No sign-in method is turned on for this address. An operator sets CHECKSTEAD_GITHUB_CLIENT_ID or CHECKSTEAD_ENTRA_CLIENT_ID, or opens the server on this computer."));
        return;
      }
      options.replaceChildren(...buttons);
    },
    (failure) => {
      options.replaceChildren(h("p", { class: "error-text" }, `Sign-in methods could not be loaded: ${failure.message}`));
    },
  );
  return h("main", { class: "gate", id: "main" }, card);
}

/**
 * Azure DevOps has no sign-in redirect Checkstead can use, so a person proves
 * who they are with an Azure DevOps access token (PAT). The server shows this only once
 * an administrator has added an Azure DevOps login.
 * @param {Context} ctx
 * @param {HTMLElement} error
 */
function azureDevOpsForm(ctx, error) {
  const organization = h("input", { type: "text", id: "azure-organization", required: true, autocomplete: "off", spellcheck: "false", placeholder: "contoso" });
  const token = h("input", { type: "password", id: "azure-token", required: true, autocomplete: "off", spellcheck: "false" });
  const submit = h("button", { type: "submit", class: "btn" }, icon("lock"), "Sign in with Azure DevOps");
  const form = h(
    "form",
    { class: "azure-signin", "aria-labelledby": "azure-head" },
    h("h2", { id: "azure-head" }, "Azure DevOps"),
    h("label", { class: "field", for: "azure-organization" }, "Organization name", organization),
    h("label", { class: "field", for: "azure-token" }, "Access token (PAT)", token),
    h("p", { class: "muted small" }, "A token with only the User Profile (Read) scope is enough. Checkstead checks it once to learn who you are and does not store it."),
    submit,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.setAttribute("disabled", "");
    error.hidden = true;
    try {
      await ctx.api.signInWithToken({
        provider: "azure-devops",
        organization: /** @type {HTMLInputElement} */ (organization).value.trim(),
        token: /** @type {HTMLInputElement} */ (token).value.trim(),
      });
      /** @type {HTMLInputElement} */ (token).value = "";
      await ctx.signedIn();
    } catch (failure) {
      /** @type {HTMLInputElement} */ (token).value = "";
      error.textContent = /** @type {Error} */ (failure).message;
      error.hidden = false;
      submit.removeAttribute("disabled");
    }
  });
  return form;
}
