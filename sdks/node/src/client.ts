import { randomUUID } from "node:crypto";

import {
  SynapsePayApiError, SynapsePayAuthenticationError, SynapsePayConnectionError, SynapsePayError,
  SynapsePayInvalidRequestError,
} from "./errors.js";

export interface ClientOptions {
  /** Defaults to the sandbox, http://localhost:8000. */
  apiBase?: string;
  /** Retries after a network failure, a 5xx or a retryable answer. Default 3. */
  maxRetries?: number;
  /** Per attempt. Default 30 s. */
  timeoutMs?: number;
  /** For tests. */
  fetch?: typeof fetch;
  /** Base backoff; attempt n waits about base × 2^(n-1). Default 500 ms. */
  retryBaseMs?: number;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class HttpClient {
  readonly apiBase: string;
  private readonly secretKey: string;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private readonly retryBaseMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(secretKey: string, options: ClientOptions = {}) {
    if (!secretKey || !secretKey.startsWith("sk_")) {
      throw new SynapsePayAuthenticationError("A secret API key (sk_...) is required. Never use it in a browser or app.",
                                              { code: "UNAUTHENTICATED" });
    }
    this.secretKey = secretKey;
    this.apiBase = (options.apiBase ?? "http://localhost:8000").replace(/\/+$/, "");
    this.maxRetries = options.maxRetries ?? 3;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retryBaseMs = options.retryBaseMs ?? 500;
    this.fetchImpl = options.fetch ?? fetch;
  }

  /**
   * Sends a request, retrying network failures, 5xx and retryable answers with exponential backoff and jitter.
   * Every POST carries an idempotency key in its body, and the same body is resent on every attempt, so a retry
   * can never create a second intent or charge twice.
   */
  async request<T>(method: "GET" | "POST", path: string, body?: Record<string, unknown>): Promise<T> {
    let lastError: SynapsePayError | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const backoff = this.retryBaseMs * 2 ** (attempt - 1);
        await sleep(backoff / 2 + Math.random() * backoff / 2);
      }
      let response: Response;
      try {
        response = await this.fetchImpl(`${this.apiBase}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.secretKey}`,
            "content-type": "application/json",
            "user-agent": "synapsepay-node/0.1.0",
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (e) {
        lastError = new SynapsePayConnectionError("Couldn't reach Synapse Pay.", { code: "ERR_NETWORK", retryable: true });
        continue;
      }
      const text = await response.text();
      let data: any = {};
      try { data = text ? JSON.parse(text) : {}; } catch { /* non-JSON error page */ }
      if (response.ok) return data as T;
      const opts = { code: data.error_code ?? `HTTP_${response.status}`, category: data.error_category,
                     retryable: Boolean(data.retryable) || response.status >= 500, statusCode: response.status };
      const message = data.error_message ?? `Synapse Pay answered HTTP ${response.status}`;
      if (response.status === 401 || response.status === 403) throw new SynapsePayAuthenticationError(message, opts);
      if (response.status >= 500) { lastError = new SynapsePayApiError(message, opts); continue; }
      // A 409 with retryable: the same request is still running; asking again shortly gets its result.
      if (opts.retryable) { lastError = new SynapsePayApiError(message, opts); continue; }
      throw new SynapsePayInvalidRequestError(message, opts);
    }
    throw lastError!;
  }

  static newIdempotencyKey(): string {
    return randomUUID();
  }
}
