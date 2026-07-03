/**
 * Optional drop-in UI — custom elements layered over the headless API:
 *
 *   <wisp-button action="signup"></wisp-button>   create a passkey account
 *   <wisp-button action="signin"></wisp-button>   return with a passkey
 *   <wisp-button action="guest"></wisp-button>    start a guest session
 *   <wisp-button action="signout"></wisp-button>  sign out
 *   <wisp-code-signup></wisp-code-signup>         code account + shown-once panel
 *   <wisp-code-signin></wisp-code-signin>         paste-a-saved-code form
 *   <wisp-status></wisp-status>                   live session chip
 *
 * The page listens for bubbling events instead of wiring callbacks:
 *   "wisp-success"  detail: { userId, confidence, code? }
 *   "wisp-error"    detail: { message }
 *   "wisp-signout"  (no detail)
 *
 * Theme with CSS custom properties (--wisp-accent, --wisp-accent-text,
 * --wisp-border, --wisp-error, --wisp-radius) or restyle any piece via
 * ::part(button | input | panel | code | chip).
 *
 * Classes are required here — Custom Elements must extend HTMLElement (the
 * sanctioned exception in docs/rules/typescript.md → Clean Code). They stay
 * thin: rendering and busy/error handling live in the plain functions below.
 */
import {
  type Account,
  signIn,
  signInWithCode,
  signOut,
  signUp,
  signUpAsGuest,
  signUpWithCode,
  whoAmI,
} from "./index.js";

const STYLE = `
  :host { display: inline-block; font: inherit; }
  button {
    font: inherit; cursor: pointer; border: 1px solid transparent;
    background: var(--wisp-accent, #2563eb); color: var(--wisp-accent-text, #fff);
    border-radius: var(--wisp-radius, 8px); padding: 0.55em 1.1em;
    transition: transform 0.12s ease, filter 0.16s, opacity 0.16s;
  }
  button:hover:not(:disabled) { filter: brightness(1.18); }
  button:active:not(:disabled) { transform: translateY(1px) scale(0.99); }
  button:focus-visible { outline: 2px solid var(--wisp-accent, #2563eb); outline-offset: 2px; }
  button:disabled { cursor: wait; opacity: 0.6; }
  button.quiet {
    background: transparent; border-color: var(--wisp-border, #9ca3af); color: inherit;
  }
  input {
    font: inherit; color: inherit; background: transparent;
    /* Prefer ~17em but allow shrinking so the form stays inside narrow
       phones instead of forcing the host wider than the viewport. */
    flex: 1 1 17em; min-width: 0; box-sizing: border-box;
    border: 1px solid var(--wisp-border, #9ca3af);
    border-radius: var(--wisp-radius, 8px); padding: 0.5em 0.7em;
  }
  .row { align-items: center; display: flex; flex-wrap: wrap; gap: 0.5em; }
  .error { color: var(--wisp-error, #b3261e); display: block; font-size: 0.85em; margin-top: 0.35em; }
  .error:empty { display: none; }
  .panel {
    border: 1px dashed var(--wisp-border, #9ca3af);
    border-radius: var(--wisp-radius, 8px); margin-top: 0.6em; padding: 0.8em;
  }
  .panel[hidden] { display: none; }
  .panel code { font-size: 1.05em; overflow-wrap: anywhere; user-select: all; }
  .panel .row { margin-top: 0.6em; }
  .note { display: block; font-size: 0.85em; margin-bottom: 0.5em; opacity: 0.8; }
  .chip {
    border: 1px solid var(--wisp-border, #9ca3af); border-radius: 999px;
    display: inline-block; font-size: 0.85em; padding: 0.25em 0.8em;
  }
`;

/** Attach a shadow root with the shared stylesheet. The markup is always a
 *  static template — anything dynamic is set via textContent afterwards. */
function mount(host: HTMLElement, html: string): ShadowRoot {
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `<style>${STYLE}</style>${html}`;
  return root;
}

function emit(
  host: HTMLElement,
  type: "wisp-error" | "wisp-signout" | "wisp-success",
  detail?: unknown,
): void {
  host.dispatchEvent(new CustomEvent(type, { bubbles: true, composed: true, detail }));
}

/** Shared busy/error wrapper: disables the button while working, shows the
 *  failure inline, and mirrors it as a "wisp-error" event. The try/catch is
 *  the sanctioned boundary kind — a click handler can't let errors escape. */
async function runAction(
  host: HTMLElement,
  button: HTMLButtonElement,
  errorLine: HTMLElement,
  work: () => Promise<void>,
): Promise<void> {
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  errorLine.textContent = "";
  try {
    await work();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    errorLine.textContent = message;
    emit(host, "wisp-error", { message });
  }
  button.disabled = false;
  button.removeAttribute("aria-busy");
}

const ERROR_LINE = '<span class="error" part="error" role="status" aria-live="polite"></span>';

interface ClickAction {
  label: string;
  quiet: boolean;
  run(): Promise<Account | null>;
}

/** null from run() means "signed out" rather than "signed in as …". */
const CLICK_ACTIONS: Record<string, ClickAction> = {
  guest: { label: "Continue as guest", quiet: false, run: signUpAsGuest },
  signin: { label: "Sign in with passkey", quiet: false, run: signIn },
  signout: {
    label: "Sign out",
    quiet: true,
    run: async () => {
      await signOut();
      return null;
    },
  },
  signup: { label: "Create anonymous account", quiet: false, run: signUp },
};

class WispButton extends HTMLElement {
  connectedCallback(): void {
    if (this.shadowRoot) return; // re-connects must not rebuild
    const action = CLICK_ACTIONS[this.getAttribute("action") ?? ""];
    const root = mount(this, `<button part="button" type="button"></button>${ERROR_LINE}`);
    const button = root.querySelector("button");
    const errorLine = root.querySelector(".error");
    if (!button || !(errorLine instanceof HTMLElement)) return;
    if (!action) {
      button.disabled = true;
      button.textContent = "wisp-button: unknown action";
      return;
    }
    if (action.quiet) button.classList.add("quiet");
    button.textContent = this.getAttribute("label") ?? action.label;
    button.addEventListener("click", () =>
      runAction(this, button, errorLine, async () => {
        const account = await action.run();
        if (account) emit(this, "wisp-success", account);
        else emit(this, "wisp-signout");
      }),
    );
  }
}

class WispCodeSignup extends HTMLElement {
  connectedCallback(): void {
    if (this.shadowRoot) return;
    const root = mount(
      this,
      `<button part="button" type="button"></button>
       <div class="panel" part="panel" hidden>
         <span class="note">Your account code — shown once, never again. Save it somewhere
         safe: anyone holding it holds the account.</span>
         <code part="code"></code>
         <div class="row">
           <button part="button" type="button" class="copy quiet">Copy</button>
           <button part="button" type="button" class="done quiet">I saved it</button>
         </div>
       </div>${ERROR_LINE}`,
    );
    const start = root.querySelector("button");
    const panel = root.querySelector(".panel");
    const codeLine = root.querySelector("code");
    const copy = root.querySelector(".copy");
    const done = root.querySelector(".done");
    const errorLine = root.querySelector(".error");
    const fine =
      start &&
      codeLine &&
      panel instanceof HTMLElement &&
      copy instanceof HTMLButtonElement &&
      done instanceof HTMLButtonElement &&
      errorLine instanceof HTMLElement;
    if (!fine) return;
    start.textContent = this.getAttribute("label") ?? "Get an account code";
    start.addEventListener("click", () =>
      runAction(this, start, errorLine, async () => {
        const created = await signUpWithCode();
        codeLine.textContent = created.code;
        start.hidden = true; // a second click would mint a second account
        panel.hidden = false;
        emit(this, "wisp-success", created);
      }),
    );
    copy.addEventListener("click", () =>
      runAction(this, copy, errorLine, async () => {
        await navigator.clipboard.writeText(codeLine.textContent ?? "");
        copy.textContent = "Copied ✓";
      }),
    );
    done.addEventListener("click", () => {
      panel.hidden = true;
    });
  }
}

class WispCodeSignin extends HTMLElement {
  connectedCallback(): void {
    if (this.shadowRoot) return;
    const root = mount(
      this,
      `<form class="row">
         <input part="input" placeholder="wisp-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx"
           autocomplete="off" spellcheck="false" aria-label="Account code">
         <button part="button" type="submit"></button>
       </form>${ERROR_LINE}`,
    );
    const form = root.querySelector("form");
    const input = root.querySelector("input");
    const button = root.querySelector("button");
    const errorLine = root.querySelector(".error");
    if (!form || !input || !button || !(errorLine instanceof HTMLElement)) return;
    button.textContent = this.getAttribute("label") ?? "Sign in with code";
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void runAction(this, button, errorLine, async () => {
        const account = await signInWithCode(input.value);
        input.value = "";
        emit(this, "wisp-success", account);
      });
    });
  }
}

class WispStatus extends HTMLElement {
  /** Arrow field so the same reference works for add/removeEventListener. */
  private refresh = async (): Promise<void> => {
    const chip = this.shadowRoot?.querySelector(".chip");
    if (!chip) return;
    // .catch, not try/catch: a dead server means "signed out", not a crash.
    const account = await whoAmI().catch(() => null);
    chip.textContent = account ? `signed in · ${account.confidence}` : "signed out";
  };

  connectedCallback(): void {
    if (!this.shadowRoot) mount(this, '<span class="chip" part="chip">…</span>');
    addEventListener("wisp-success", this.refresh);
    addEventListener("wisp-signout", this.refresh);
    void this.refresh();
  }

  disconnectedCallback(): void {
    removeEventListener("wisp-success", this.refresh);
    removeEventListener("wisp-signout", this.refresh);
  }
}

// Side-effect registration: index.ts imports this module once, so the elements
// exist wherever the script tag does. Guarded for non-DOM environments and
// against double registration (two script tags must not throw).
if (typeof customElements !== "undefined" && !customElements.get("wisp-button")) {
  customElements.define("wisp-button", WispButton);
  customElements.define("wisp-code-signin", WispCodeSignin);
  customElements.define("wisp-code-signup", WispCodeSignup);
  customElements.define("wisp-status", WispStatus);
}
