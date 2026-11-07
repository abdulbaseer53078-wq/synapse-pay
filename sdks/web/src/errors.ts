/** Standard error codes: show the matching message to the customer. `apiCode` is Synapse's raw error_code. */
export type SynapsePayErrorCode =
  | "ERR_NETWORK"               // "Check your internet connection and try again."
  | "ERR_CARD_INCOMPLETE"       // the card form shows what's missing
  | "ERR_CARD_DECLINED"         // "Your bank declined the card. Try another card."
  | "ERR_AUTHENTICATION_FAILED" // "Your bank couldn't verify this payment. Try again or use another card."
  | "ERR_CANCELED"              // the customer closed the bank's page, or the merchant canceled
  | "ERR_TIMEOUT"               // still not done after the wait you allowed
  | "ERR_INVALID_REQUEST"       // a bug in the integration (wrong client secret, expired intent...)
  | "ERR_SYSTEM_ERROR";         // "Something went wrong. Try again in a moment."

export interface SynapsePayError {
  code: SynapsePayErrorCode;
  message: string;
  /** Safe to try again (same client secret). */
  retryable: boolean;
  apiCode?: string;
  category?: string;
}

interface ApiError { error_code?: string; code?: string; error_message?: string; message?: string;
                     error_category?: string; category?: string; retryable?: boolean }

export function fromApi(e: ApiError | undefined): SynapsePayError {
  const apiCode = e?.error_code ?? e?.code;
  const category = e?.error_category ?? e?.category;
  const message = e?.error_message ?? e?.message ?? "Something went wrong.";
  const retryable = Boolean(e?.retryable);
  let code: SynapsePayErrorCode;
  if (apiCode?.startsWith("ERR_")) code = apiCode as SynapsePayErrorCode;
  else if (apiCode === "AUTHENTICATION_FAILED") code = "ERR_AUTHENTICATION_FAILED";
  else if (category === "SOFT_DECLINE" || category === "HARD_DECLINE") code = "ERR_CARD_DECLINED";
  else if (category === "VALIDATION_ERROR" || category === "AUTHENTICATION_ERROR") code = "ERR_INVALID_REQUEST";
  else code = "ERR_SYSTEM_ERROR";
  return { code, message, retryable: retryable || code === "ERR_NETWORK", apiCode, category };
}
