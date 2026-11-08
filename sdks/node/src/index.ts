import { HttpClient, type ClientOptions } from "./client.js";
import type { PaymentIntent, PaymentIntentCreateParams, RecoveryStats } from "./types.js";
import { constructEvent } from "./webhooks.js";

export * from "./errors.js";
export type * from "./types.js";
export type { ClientOptions } from "./client.js";

class PaymentIntents {
  constructor(private readonly http: HttpClient) {}

  /**
   * Creates a payment intent. Hand `client_secret` to the customer's page or app, where the Synapse Pay web or
   * mobile SDK takes the card. Retried automatically with the same idempotency key, so it's never duplicated.
   */
  create(params: PaymentIntentCreateParams): Promise<PaymentIntent> {
    const { idempotency_key, currency, ...rest } = params;
    return this.http.request<PaymentIntent>("POST", "/api/v1/payment_intents", {
      idempotency_key: idempotency_key ?? HttpClient.newIdempotencyKey(),
      currency: currency ?? "INR",
      ...rest,
    });
  }

  retrieve(id: string): Promise<PaymentIntent> {
    return this.http.request<PaymentIntent>("GET", `/api/v1/payment_intents/${encodeURIComponent(id)}`);
  }

  /** Only while it's waiting for the customer (REQUIRES_PAYMENT_METHOD or REQUIRES_ACTION). */
  cancel(id: string): Promise<PaymentIntent> {
    return this.http.request<PaymentIntent>("POST", `/api/v1/payment_intents/${encodeURIComponent(id)}/cancel`);
  }
}

class Merchants {
  constructor(private readonly http: HttpClient) {}

  /** What failover saved you over the last `days` (1–90, default 30). */
  recoveryStats(options: { days?: number } = {}): Promise<RecoveryStats> {
    return this.http.request<RecoveryStats>("GET", `/api/v1/merchants/me/recovery-stats?days=${options.days ?? 30}`);
  }
}

export class SynapsePay {
  readonly paymentIntents: PaymentIntents;
  readonly merchants: Merchants;
  readonly webhooks = { constructEvent };

  constructor(secretKey: string, options: ClientOptions = {}) {
    const http = new HttpClient(secretKey, options);
    this.paymentIntents = new PaymentIntents(http);
    this.merchants = new Merchants(http);
  }
}

export default SynapsePay;
