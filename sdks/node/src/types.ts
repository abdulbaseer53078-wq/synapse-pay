export type Currency = "INR";
export type CaptureMode = "AUTO" | "MANUAL";

export type PaymentIntentStatus =
  | "REQUIRES_PAYMENT_METHOD"
  | "REQUIRES_ACTION"
  | "PROCESSING"
  | "SUCCEEDED"
  | "CANCELED";

export type TransactionStatus =
  | "INITIATED" | "PENDING" | "AUTHORIZED" | "CAPTURED" | "SETTLED" | "VOIDED" | "FAILED" | "REFUNDED"
  | "PARTIALLY_REFUNDED";

export interface ApiErrorBody {
  error_code: string;
  error_message: string;
  error_category: "SOFT_DECLINE" | "HARD_DECLINE" | "SYSTEM_ERROR" | "VALIDATION_ERROR" | "AUTHENTICATION_ERROR";
  retryable: boolean;
}

export interface PaymentIntent {
  id: string;
  status: PaymentIntentStatus;
  /** Smallest currency unit: 50000 = ₹500.00. */
  amount: number;
  currency: Currency;
  capture_mode: CaptureMode;
  /** Give this to the customer's page or app; it lets them pay this one intent and nothing else. */
  client_secret: string;
  description?: string;
  metadata: Record<string, string>;
  webhook_url?: string;
  /** Set when the intent is paid on a physical terminal. */
  terminal_id?: string;
  transaction_id?: string;
  last_payment_error?: ApiErrorBody;
  card?: { bin: string; last4: string };
  next_action?: { type: "THREE_DS_CHALLENGE"; url: string };
  created_at: string;
  updated_at: string;
  expires_at: string;
}

export interface PaymentIntentCreateParams {
  /** Smallest currency unit: 50000 = ₹500.00. At least 100 (₹1). */
  amount: number;
  currency?: Currency;
  capture_mode?: CaptureMode;
  description?: string;
  metadata?: Record<string, string>;
  /** Where Synapse POSTs the signed final status. HTTPS. */
  webhook_url?: string;
  /** Take the payment on this terminal instead of a web or app card form. */
  terminal_id?: string;
  /** Generated for you. Pass your own (a UUID) to make a create safe to repeat across process restarts. */
  idempotency_key?: string;
}

/** The webhook body: the transaction's final status (spec: TransactionResponse). */
export interface TransactionEvent {
  transaction_id: string;
  idempotency_key: string;
  status: TransactionStatus;
  amount: number;
  currency: Currency;
  payment_method: "CARD" | "UPI" | "WALLET" | "QR" | "OFFLINE";
  payment_intent_id?: string;
  method_reference?: string;
  auth_code?: string;
  error?: ApiErrorBody;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}
