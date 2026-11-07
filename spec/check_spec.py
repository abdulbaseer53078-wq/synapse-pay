"""Validates the spec's own examples (Task 1.7 fixtures) and the rules contract tests rely on.

Usage: python spec/check_spec.py [spec/openapi.yaml]
"""
import sys

import yaml
from jsonschema import Draft202012Validator

spec = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else "spec/openapi.yaml", encoding="utf-8"))
components = spec["components"]


def validator(name):
    return Draft202012Validator({"$ref": f"#/components/schemas/{name}", "components": components},
                                format_checker=Draft202012Validator.FORMAT_CHECKER)


request, response, error, capability = (validator(n) for n in
                                        ("TransactionRequest", "TransactionResponse", "Error", "CapabilityDescriptor"))

# Every example must validate against its schema.
examples = {name: ex["value"] for name, ex in components["examples"].items()}
for name, value in examples.items():
    if name.endswith("Request"):
        request.validate(value)
    elif name.endswith("Capabilities"):
        capability.validate(value)
    else:
        response.validate(value)
for ex in components["responses"]["Error"]["content"]["application/json"]["examples"].values():
    error.validate(ex["value"])

methods = components["schemas"]["TransactionRequest"]["properties"]["payment_method"]["enum"]
for kind in ("Request", "Capabilities"):
    covered = {examples[f"{m.capitalize()}{kind}"]["payment_method"] for m in methods}
    assert covered == set(methods), f"methods without a {kind} example: {set(methods) - covered}"

# A descriptor's refund flags must match the refund transitions it lists.
for m in methods:
    d = examples[f"{m.capitalize()}Capabilities"]
    targets = {t["to"] for t in d["transitions"]}
    assert ("REFUNDED" in targets) == d["supports_refund"], f"{m}: supports_refund vs transitions"
    assert ("PARTIALLY_REFUNDED" in targets) == d["supports_partial_refund"], f"{m}: supports_partial_refund vs transitions"


def expect(v, ok, doc, label):
    assert v.is_valid(doc) == ok, f"{label}: expected {'valid' if ok else 'invalid'}"


card, upi = examples["CardRequest"], examples["UpiRequest"]
upi_details = upi["method_details"]

# Required fields, enums and money type.
for field in components["schemas"]["TransactionRequest"]["required"]:
    expect(request, False, {k: v for k, v in card.items() if k != field}, f"request missing {field}")
expect(request, False, {**card, "payment_method": "CASH"}, "unknown payment_method")
expect(request, False, {**card, "amount": 500.5}, "float amount")
expect(request, False, {**card, "amount": 0}, "zero amount")
expect(request, False, {**card, "webhook_url": "http://merchant.example.com"}, "non-https webhook")

# Discriminated union: details must match the method.
expect(request, False, {**card, "method_details": upi_details}, "CARD with UPI details")
expect(request, False, {**card, "method_details": {**card["method_details"], "card_expiry": "13/28"}}, "bad expiry")
expect(request, False, {**upi, "method_details": {**upi_details, "qr_data": "q"}}, "UPI with qr_data")
expect(request, False, {**upi, "method_details": {"flow_type": "COLLECT"}}, "UPI without vpa")
qr = examples["QrRequest"]
expect(request, False, {**qr, "method_details": {**qr["method_details"], "qr_type": "UPI_QR"}}, "QR with removed qr_type")
expect(request, False, {**qr, "method_details": {**qr["method_details"], "qr_encoded_rail": "CASH"}}, "unknown QR rail")
expect(request, False, {**upi, "method_details": {**upi_details, "flow_type": "MANDATE"}}, "MANDATE without details")
expect(request, True, {**upi, "method_details": {**upi_details, "flow_type": "MANDATE", "mandate_details": {}}}, "MANDATE")
expect(request, False, {**upi, "method_details": {**upi_details, "mandate_details": {}}}, "mandate_details on COLLECT")

# Response: status enum and the FAILED <-> error rule.
ok, failed = examples["CardSuccess"], examples["CardFailure"]
expect(response, False, {**ok, "status": "DONE"}, "unknown status")
expect(response, False, {**ok, "error": failed["error"]}, "error on a non-FAILED response")
expect(response, False, {k: v for k, v in failed.items() if k != "error"}, "FAILED without error")

# Error taxonomy.
for field in components["schemas"]["Error"]["required"]:
    expect(error, False, {k: v for k, v in failed["error"].items() if k != field}, f"error missing {field}")
expect(error, False, {**failed["error"], "error_category": "MAYBE"}, "unknown error_category")

print(f"OK: {len(examples)} examples valid, all rule checks passed")
