"""Payment method adapters (Stage 1, Step 8). One module per rail; the registry in main.py wires them.

Adding a method: write a class with `method`, validate/initiate/capture/refund/status/handle_webhook, register
it in main.py. TransactionService is not touched.
"""
