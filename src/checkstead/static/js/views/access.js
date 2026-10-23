// @ts-check
// Access: who can sign in, and who administers this server.

import { avatar, dataTable, stateBlock, timeEl } from "../components.js";
import { h } from "../dom.js";
import { providerName } from "../format.js";
import { pageHead, withLoad } from "./common.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").User} User */

const PROVIDERS = [["github", "GitHub"], ["azure-devops", "Azure DevOps"], ["entra", "Microsoft Entra"]];

/** @param {Context} ctx */
export function renderAccess(ctx) {
  if (!ctx.state.user || ctx.state.user.role !== "admin") {
    return h("div", null, pageHead("Access"), stateBlock({ iconName: "lock", title: "Only administrators manage access", body: "Ask an administrator of this server to add people or change roles." }));
  }
  return h(
    "div",
    null,
    pageHead("Access", "People who can sign in. Each signs in with their own GitHub, Azure DevOps, or Microsoft Entra account; nobody can sign in until they are added here."),
    addForm(ctx),
    withLoad(ctx, "users", (/** @type {{users: User[]}} */ data) => users(ctx, data.users)),
    uploadTokens(ctx),
  );
}

/**
 * The token from the last create, shown until the person leaves the page.
 * @type {{id: number, token: string} | null}
 */
let revealed = null;

/** Drop the shown token; app.js calls this when another page renders. */
export function forgetUploadToken() {
  revealed = null;
}

/** @param {Context} ctx */
function uploadTokens(ctx) {
  const name = h("input", { type: "text", name: "token-name", id: "token-name", required: true, autocomplete: "off", placeholder: "Proarc-Products pipelines" });
  const error = h("p", { class: "error-text", role: "alert", hidden: true });
  const submit = h("button", { type: "submit", class: "btn primary" }, "Create upload token");
  const form = h(
    "form",
    { class: "form-row" },
    h("label", { class: "field", for: "token-name" }, "Token name", name),
    submit,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    submit.setAttribute("disabled", "");
    try {
      const created = await ctx.api.createUploadToken(/** @type {HTMLInputElement} */ (name).value.trim());
      revealed = { id: created.uploadToken.id, token: created.token };
      ctx.notify(`Created ${created.uploadToken.name}. Copy it now; it is not shown again.`);
      ctx.load("uploadTokens", true);
    } catch (failure) {
      error.textContent = /** @type {Error} */ (failure).message;
      error.hidden = false;
      submit.removeAttribute("disabled");
    }
  });
  return h(
    "section",
    { class: "section panel", "aria-labelledby": "tokens-head" },
    h("h2", { id: "tokens-head" }, "Upload tokens"),
    h(
      "p",
      { class: "muted" },
      "A pipeline sends its report with one of these, the way a SonarQube analysis is sent with a SonarQube token. Store it as the secret pipeline variable CHECKSTEAD_UPLOAD_TOKEN and set CHECKSTEAD_SERVER to this server's address.",
    ),
    form,
    error,
    revealed ? revealBox(ctx, revealed.token) : null,
    withLoad(ctx, "uploadTokens", (/** @type {{uploadTokens: import("../api.js").UploadToken[]}} */ data) => tokenTable(ctx, data.uploadTokens)),
  );
}

/**
 * @param {Context} ctx
 * @param {string} token
 */
function revealBox(ctx, token) {
  const field = h("input", { type: "text", id: "new-token", readonly: true, value: token, class: "id", "aria-label": "New upload token", spellcheck: "false" });
  const copy = h("button", { type: "button", class: "btn" }, "Copy");
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(token);
      ctx.notify("Copied the upload token.");
    } catch {
      /** @type {HTMLInputElement} */ (field).select();
      ctx.notify("Select the token and copy it.");
    }
  });
  return h(
    "div",
    { class: "banner info", role: "status" },
    h("p", null, h("strong", null, "Copy this token now."), " It is shown once. The server keeps only its hash.", h("span", { class: "form-row" }, field, copy)),
  );
}

/**
 * @param {Context} ctx
 * @param {import("../api.js").UploadToken[]} list
 */
function tokenTable(ctx, list) {
  return dataTable({
    caption: "Upload tokens",
    columns: [
      { key: "name", label: "Name", cell: (token) => token.name },
      { key: "created", label: "Created", cell: (token) => timeEl(token.createdAt, ctx.now) },
      { key: "used", label: "Last used", cell: (token) => (token.lastUsedAt ? timeEl(token.lastUsedAt, ctx.now) : h("span", { class: "muted" }, "never")) },
      { key: "revoke", label: "Revoke", cell: (token) => revokeControl(ctx, token) },
    ],
    groups: [{ label: null, rows: list }],
    empty: "No upload tokens yet. Pipelines cannot send reports until one exists.",
  });
}

/**
 * Two-step revoke: the first press asks, the second revokes.
 * @param {Context} ctx
 * @param {import("../api.js").UploadToken} token
 */
function revokeControl(ctx, token) {
  const button = h("button", { type: "button", class: "btn danger", "aria-label": `Revoke ${token.name}` }, "Revoke");
  let armed = false;
  button.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      button.textContent = "Confirm revoke";
      button.setAttribute("aria-label", `Confirm revoking ${token.name}`);
      return;
    }
    button.setAttribute("disabled", "");
    try {
      await ctx.api.revokeUploadToken(token.id);
      if (revealed && revealed.id === token.id) revealed = null;
      ctx.notify(`Revoked ${token.name}. Pipelines using it can no longer send reports.`);
      ctx.load("uploadTokens", true);
    } catch (error) {
      ctx.notify(/** @type {Error} */ (error).message);
      button.removeAttribute("disabled");
    }
  });
  return button;
}

/** @param {Context} ctx */
function addForm(ctx) {
  const provider = h("select", { name: "provider", id: "add-provider" }, PROVIDERS.map(([value, label]) => h("option", { value }, label)));
  const login = h("input", { type: "text", name: "login", id: "add-login", required: true, autocomplete: "off", spellcheck: "false" });
  const role = h("select", { name: "role", id: "add-role" }, h("option", { value: "user" }, "Member"), h("option", { value: "admin" }, "Administrator"));
  const error = h("p", { class: "error-text", role: "alert", hidden: true });
  const submit = h("button", { type: "submit", class: "btn primary" }, "Add person");
  const form = h(
    "form",
    { class: "section panel", "aria-labelledby": "add-head" },
    h("h2", { id: "add-head" }, "Add a person"),
    h(
      "div",
      { class: "form-row" },
      h("label", { class: "field", for: "add-provider" }, "Account type", provider),
      h("label", { class: "field", for: "add-login" }, "Login or email", login),
      h("label", { class: "field", for: "add-role" }, "Role", role),
      submit,
    ),
    error,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    submit.setAttribute("disabled", "");
    try {
      const { user } = await ctx.api.addUser({
        provider: /** @type {HTMLSelectElement} */ (provider).value,
        login: /** @type {HTMLInputElement} */ (login).value.trim(),
        role: /** @type {HTMLSelectElement} */ (role).value,
      });
      ctx.notify(`Added ${user.login}.`);
      ctx.load("users", true);
    } catch (failure) {
      error.textContent = /** @type {Error} */ (failure).message;
      error.hidden = false;
      submit.removeAttribute("disabled");
    }
  });
  return form;
}

/**
 * @param {Context} ctx
 * @param {User[]} list
 */
function users(ctx, list) {
  return dataTable({
    caption: "People who can sign in",
    columns: [
      { key: "name", label: "Name", cell: (user) => h("span", { class: "person" }, avatar(user, "sm"), h("span", null, h("strong", null, user.displayName || user.login), ctx.state.user && ctx.state.user.id === user.id ? h("span", { class: "tag" }, "You") : null, h("br"), h("span", { class: "muted small id" }, user.login))) },
      { key: "provider", label: "Account type", cell: (user) => providerName(user.provider) },
      { key: "role", label: "Role", cell: (user) => roleControl(ctx, user) },
      { key: "remove", label: "Remove", cell: (user) => removeControl(ctx, user) },
    ],
    groups: [{ label: null, rows: list }],
    empty: "Nobody has been added yet.",
  });
}

/**
 * @param {Context} ctx
 * @param {User} user
 */
function roleControl(ctx, user) {
  const next = user.role === "admin" ? "user" : "admin";
  const self = ctx.state.user && ctx.state.user.id === user.id;
  // The accessible name starts with the visible text (WCAG 2.5.3).
  const current = user.role === "admin" ? "Administrator" : "Member";
  const button = h("button", { type: "button", class: "btn", "aria-label": `${current}: make ${user.login} ${next === "admin" ? "an administrator" : "a member"}` }, current);
  button.addEventListener("click", async () => {
    try {
      await ctx.api.setRole(user.id, next);
      ctx.notify(`${user.login} is now ${next === "admin" ? "an administrator" : "a member"}.`);
      ctx.load("users", true);
      if (self) await ctx.signedIn();
    } catch (error) {
      ctx.notify(/** @type {Error} */ (error).message);
    }
  });
  return button;
}

/**
 * Two-step removal: the first press asks, the second removes.
 * @param {Context} ctx
 * @param {User} user
 */
function removeControl(ctx, user) {
  const button = h("button", { type: "button", class: "btn danger", "aria-label": `Remove ${user.login}` }, "Remove");
  let armed = false;
  button.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      button.textContent = "Confirm removal";
      button.setAttribute("aria-label", `Confirm removing ${user.login}`);
      return;
    }
    button.setAttribute("disabled", "");
    try {
      await ctx.api.removeUser(user.id);
      ctx.notify(`Removed ${user.login}.`);
      ctx.load("users", true);
    } catch (error) {
      ctx.notify(/** @type {Error} */ (error).message);
      button.removeAttribute("disabled");
    }
  });
  return button;
}
