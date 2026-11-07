import { fromApi, type SynapsePayError } from "./errors.js";

export type { SynapsePayError, SynapsePayErrorCode } from "./errors.js";

export type PaymentIntentStatus = "REQUIRES_PAYMENT_METHOD" | "REQUIRES_ACTION" | "PROCESSING" | "SUCCEEDED" | "CANCELED";

/** What a customer's page may see of a payment intent. */
export interface PaymentIntent {
  id: string;
  status: PaymentIntentStatus;
  amount: number;
  currency: string;
  transaction_id?: string;
  card?: { bin: string; last4: string };
  last_payment_error?: { error_code: string; error_message: string; error_category: string; retryable: boolean };
  next_action?: { type: "THREE_DS_CHALLENGE"; url: string };
  updated_at: string;
}

/** Either `paymentIntent` (check its status) or `error`. PROCESSING means the bank's answer is late: wait for
 * your server's webhook rather than charging again. */
export interface PaymentResult {
  paymentIntent?: PaymentIntent;
  error?: SynapsePayError;
}

export interface CardChangeEvent {
  complete: boolean;
  empty: boolean;
  brand: "VISA" | "MASTERCARD" | "RUPAY" | "AMEX" | null;
}

export interface CardElement {
  /** Resolves when the form is ready to take a card. */
  readonly ready: Promise<void>;
  clear(): void;
  focus(): void;
  destroy(): void;
}

export interface SynapsePayOptions {
  /** Synapse Pay's API origin, e.g. "https://sandbox.synapsepay.example". The card form loads from here. */
  apiBase: string;
}

interface InternalCard extends CardElement {
  frame: HTMLIFrameElement;
}

const intentIdOf = (clientSecret: string): string => {
  const id = clientSecret.split("_secret_")[0];
  if (!id || !/^pi_[0-9a-f]{32}$/.test(id) || !clientSecret.includes("_secret_")) {
    throw new Error("That isn't a payment intent client_secret.");
  }
  return id;
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function SynapsePay(options: SynapsePayOptions) {
  const apiBase = options.apiBase.replace(/\/+$/, "");
  const apiOrigin = new URL(apiBase).origin;
  let seq = 0;

  /** Messages from our frames only: right origin, right window, our protocol. */
  function listen(source: () => Window | null, handler: (data: any) => void): () => void {
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== apiOrigin || event.source !== source()) return;
      if (!event.data || event.data.source !== "synapsepay") return;
      handler(event.data);
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }

  async function retrieve(clientSecret: string): Promise<PaymentIntent> {
    const id = intentIdOf(clientSecret);
    let lastError: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt) await sleep(300 * 2 ** (attempt - 1));
      try {
        const response = await fetch(`${apiBase}/api/v1/payment_intents/${id}?client_secret=${encodeURIComponent(clientSecret)}`,
                                     { credentials: "omit" });
        const data = await response.json();
        if (response.ok) return data as PaymentIntent;
        if (response.status < 500 && !data.retryable) throw Object.assign(new Error(data.error_message), { api: data });
        lastError = data;
      } catch (e: any) {
        if (e?.api) throw e;
        lastError = e;
      }
    }
    throw Object.assign(new Error("network"), { network: true, lastError });
  }

  function result(intent: PaymentIntent): PaymentResult {
    if (intent.status === "CANCELED") {
      return { paymentIntent: intent, error: { code: "ERR_CANCELED", message: "This payment was canceled.", retryable: false } };
    }
    if (intent.status === "REQUIRES_PAYMENT_METHOD" && intent.last_payment_error) {
      return { paymentIntent: intent, error: fromApi(intent.last_payment_error) };
    }
    return { paymentIntent: intent };
  }

  const networkError = (): SynapsePayError =>
    ({ code: "ERR_NETWORK", message: "Couldn't reach Synapse Pay. Check your connection.", retryable: true });

  const caught = (e: any): PaymentResult => ({ error: e?.api ? fromApi(e.api) : networkError() });

  /** Shows the bank's 3-D Secure page in a modal and waits until the customer finishes or closes it. */
  function challenge(intent: PaymentIntent, clientSecret: string): Promise<"done" | "canceled"> {
    return new Promise((resolve) => {
      const overlay = document.createElement("div");
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-label", "Verify your payment with your bank");
      overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.55);display:flex;" +
        "align-items:center;justify-content:center;padding:16px";
      const box = document.createElement("div");
      box.style.cssText = "background:#fff;border-radius:12px;width:min(420px,100%);height:min(560px,100%);overflow:hidden;" +
        "display:flex;flex-direction:column";
      const close = document.createElement("button");
      close.type = "button";
      close.textContent = "×";
      close.setAttribute("aria-label", "Close");
      close.style.cssText = "align-self:flex-end;border:0;background:none;font-size:24px;padding:4px 12px;cursor:pointer";
      const frame = document.createElement("iframe");
      frame.title = "Bank verification";
      frame.style.cssText = "border:0;flex:1;width:100%";
      const url = new URL(apiBase + intent.next_action!.url);
      url.searchParams.set("client_secret", clientSecret);
      url.searchParams.set("parent_origin", window.location.origin);
      frame.src = url.toString();
      box.append(close, frame);
      overlay.append(box);
      document.body.append(overlay);
      const finish = (how: "done" | "canceled") => { stop(); overlay.remove(); resolve(how); };
      const stop = listen(() => frame.contentWindow, (data) => {
        if (data.type === "3ds-complete") finish(data.status === "CANCELED_BY_CUSTOMER" ? "canceled" : "done");
      });
      close.addEventListener("click", () => finish("canceled"));
    });
  }

  async function afterConfirm(intent: PaymentIntent, clientSecret: string): Promise<PaymentResult> {
    if (intent.status === "REQUIRES_ACTION" && intent.next_action?.type === "THREE_DS_CHALLENGE") {
      const how = await challenge(intent, clientSecret);
      try { intent = await retrieve(clientSecret); } catch (e) { return caught(e); }
      if (how === "canceled" && intent.status === "REQUIRES_ACTION") {
        return { paymentIntent: intent,
                 error: { code: "ERR_CANCELED", message: "Bank verification was closed before finishing.", retryable: true } };
      }
    }
    return result(intent);
  }

  return {
    /**
     * Shows Synapse Pay's card form inside `target` (an element or a CSS selector). The form runs on Synapse's
     * origin: your page never sees the card number, which keeps it out of PCI DSS scope.
     */
    mountCard(target: string | HTMLElement, opts: { onChange?: (e: CardChangeEvent) => void; height?: number } = {}): CardElement {
      const host = typeof target === "string" ? document.querySelector<HTMLElement>(target) : target;
      if (!host) throw new Error(`No element matches ${String(target)}`);
      const frame = document.createElement("iframe");
      frame.title = "Secure card payment form";
      frame.setAttribute("allow", "payment");
      frame.style.cssText = `border:0;width:100%;height:${opts.height ?? 170}px;color-scheme:normal`;
      frame.src = `${apiBase}/checkout/card-frame#origin=${encodeURIComponent(window.location.origin)}`;
      let markReady!: () => void;
      let markFailed!: (e: Error) => void;
      const ready = new Promise<void>((resolve, reject) => { markReady = resolve; markFailed = reject; });
      const stop = listen(() => frame.contentWindow, (data) => {
        if (data.type === "ready") markReady();
        if (data.type === "error") markFailed(new Error(data.error?.message ?? "Card form unavailable"));
        if (data.type === "change") opts.onChange?.({ complete: data.complete, empty: data.empty, brand: data.brand });
      });
      host.append(frame);
      const send = (message: object) => frame.contentWindow?.postMessage({ source: "synapsepay-sdk", ...message }, apiOrigin);
      const card: InternalCard = {
        frame, ready,
        clear: () => send({ type: "clear" }),
        focus: () => send({ type: "focus" }),
        destroy: () => { stop(); frame.remove(); },
      };
      return card;
    },

    /**
     * Pays the intent with the card in `card`, including the bank's 3-D Secure step when the bank asks for it.
     * Safe to call again after an error: an intent is never charged twice.
     */
    async confirmCardPayment(clientSecret: string, card: CardElement): Promise<PaymentResult> {
      const frame = (card as InternalCard).frame;
      const intentId = intentIdOf(clientSecret);
      await card.ready;
      const requestId = `${Date.now()}-${++seq}`;
      const reply = await new Promise<any>((resolve) => {
        const stop = listen(() => frame.contentWindow, (data) => {
          if (data.type === "confirm-result" && data.requestId === requestId) { stop(); resolve(data); }
        });
        frame.contentWindow!.postMessage({ source: "synapsepay-sdk", type: "confirm", requestId, intentId, clientSecret },
                                         apiOrigin);
      });
      if (reply.error) return { error: fromApi(reply.error) };
      const outcome = await afterConfirm(reply.intent as PaymentIntent, clientSecret);
      if (outcome.paymentIntent?.status === "SUCCEEDED") card.clear(); // nothing left on screen after paying
      return outcome;
    },

    /**
     * For an intent created with a terminal_id: waits while the customer pays on the terminal. Polls; resolves
     * when the payment succeeds, fails, is canceled, or `timeoutMs` (default 3 minutes) passes.
     */
    async waitForTerminalPayment(clientSecret: string,
                                 opts: { timeoutMs?: number; intervalMs?: number; onUpdate?: (i: PaymentIntent) => void } = {}):
      Promise<PaymentResult> {
      const deadline = Date.now() + (opts.timeoutMs ?? 180_000);
      let last: PaymentIntent | undefined;
      while (Date.now() < deadline) {
        try {
          const intent = await retrieve(clientSecret);
          if (!last || intent.status !== last.status || intent.updated_at !== last.updated_at) opts.onUpdate?.(intent);
          last = intent;
          if (intent.status === "SUCCEEDED" || intent.status === "CANCELED" || intent.last_payment_error) return result(intent);
        } catch (e: any) {
          if (e?.api) return caught(e);
        }
        await sleep(opts.intervalMs ?? 1500);
      }
      return { paymentIntent: last,
               error: { code: "ERR_TIMEOUT", message: "The terminal payment didn't finish in time.", retryable: true } };
    },

    /** The intent's current state, as the customer's page may see it. */
    async retrievePaymentIntent(clientSecret: string): Promise<PaymentResult> {
      try { return result(await retrieve(clientSecret)); } catch (e) { return caught(e); }
    },
  };
}

export type SynapsePayClient = ReturnType<typeof SynapsePay>;
export { fromApi };
export default SynapsePay;
