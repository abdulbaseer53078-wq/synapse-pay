/** Every error the SDK throws. `code` is the API's error_code, or ERR_NETWORK when Synapse couldn't be reached. */
export class SynapsePayError extends Error {
  readonly code: string;
  readonly category: string | undefined;
  readonly retryable: boolean;
  readonly statusCode: number | undefined;

  constructor(message: string, opts: { code: string; category?: string; retryable?: boolean; statusCode?: number }) {
    super(message);
    this.name = new.target.name;
    this.code = opts.code;
    this.category = opts.category;
    this.retryable = opts.retryable ?? false;
    this.statusCode = opts.statusCode;
  }
}

/** Invalid or missing secret key (HTTP 401/403). */
export class SynapsePayAuthenticationError extends SynapsePayError {}

/** The request was wrong: fix it, don't retry it (HTTP 400/404/409/422). */
export class SynapsePayInvalidRequestError extends SynapsePayError {}

/** Synapse couldn't be reached, even after retries. Safe to retry later with the same idempotency key. */
export class SynapsePayConnectionError extends SynapsePayError {}

/** Synapse had a problem (HTTP 5xx), even after retries. Safe to retry later with the same idempotency key. */
export class SynapsePayApiError extends SynapsePayError {}

/** A webhook's X-Signature didn't match its body: ignore the request. */
export class SynapsePaySignatureError extends SynapsePayError {}
