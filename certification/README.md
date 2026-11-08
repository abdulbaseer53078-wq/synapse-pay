# Certification test harness (Step 27)

Runs `matrix.json` through a terminal and the real payment stack (backend → card service → ISO 8583 over mutual TLS)
against `scheme_sim.py`, a strict scheme host. Its checks:

- DE 55 as strict BER-TLV, with every required tag at its expected length;
- the AID belongs to the card's scheme;
- the chip amount, currency and transaction type match DE 4, DE 49 and DE 3;
- Luhn and BIN on DE 2, expiry on DE 14.

| File | Job |
| :--- | :--- |
| `scheme_sim.py` | The strict host. Reuses `mock_host.py`'s parser and answers, and writes one evidence line per request: hex fields, PAN masked, DE 55 as tags and lengths only. |
| `matrix.json` | The cases: approvals for each scheme, USD, online PIN, insufficient funds, expired card, bad card number. |
| `harness.py` | `TerminalDriver`, `SoftwareTerminal` and `run()`, which returns the report. |

```bash
python -m pytest certification/test_scheme_sim.py                      # the simulator's own checks
cd backend && pytest tests/test_certification_harness.py                # the matrix through the real stack
```

CI (`.github/workflows/certification.yml`) runs both on every PR that touches the card path and uploads the reports.

## Approving a firmware

1. Run the matrix against the firmware. Record the report with `POST /api/v1/certification-runs` (scope
   `certification:run`). The server decides `passed` from the cases.
2. Once the scheme certifies it, a platform admin records `POST /api/v1/certifications` (`registry:admin`). This
   step is refused with 409 `CERTIFICATION_RUN_REQUIRED` unless that model and firmware's latest run passed the
   scheme.

## Not built

- **A device driver.** Today the only driver is `SoftwareTerminal`, which builds requests itself. A run it records
  is evidence for the cloud path, not for a device's firmware; the run's `driver` field says which. Add an ADB/Appium
  driver once a terminal app exists.
- **UPI cases.** NPCI certification isn't ISO 8583, so the matrix covers card schemes only, and a run never covers
  `NPCI_UPI`.
