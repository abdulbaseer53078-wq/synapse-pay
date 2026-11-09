// PR 9: card payments against the real API at load. Driven by backend/tests/test_load.py, which starts the stack
// (API → card service → mock acquirer over mutual TLS), registers an active, certified terminal, and passes:
//   API_URL, TERMINAL_ID, MERCHANT_ID, ENVELOPE (an encrypted card, as a terminal sends it)
// The API is called directly with x-terminal-id, which in production only the gateway sets after mTLS.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

export const options = {
    scenarios: {
        load_test: {
            executor: 'ramping-vus',
            startVUs: 10,
            stages: [
                { duration: __ENV.RAMP || '30s', target: 50 },
                { duration: __ENV.RAMP2 || '1m', target: 100 },
                { duration: __ENV.HOLD || '1m', target: 100 },
                { duration: '30s', target: 0 },
            ],
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.01'],
        http_req_duration: ['p(95)<500'],
        checks: ['rate>0.99'],
    },
};

export default function () {
    // A fresh idempotency key per sale, in the body (the API's contract), so every request is a real write.
    const body = JSON.stringify({
        idempotency_key: uuidv4(),
        amount: 10000,
        currency: 'INR',
        payment_method: 'CARD',
        method_details: { encrypted_card_data: __ENV.ENVELOPE, card_expiry: '08/30', card_network: 'VISA' },
        terminal_id: __ENV.TERMINAL_ID,
        merchant_id: __ENV.MERCHANT_ID,
    });
    const res = http.post(`${__ENV.API_URL}/api/v1/transactions`, body, {
        headers: { 'Content-Type': 'application/json', 'x-terminal-id': __ENV.TERMINAL_ID },
        timeout: '20s',
    });
    check(res, {
        'status is 201': (r) => r.status === 201,
        'captured': (r) => r.status === 201 && r.json('status') === 'CAPTURED',
    });
    sleep(0.5); // the cashier handing over the receipt
}
