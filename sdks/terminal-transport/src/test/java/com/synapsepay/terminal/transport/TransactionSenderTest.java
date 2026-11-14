package com.synapsepay.terminal.transport;

import static java.nio.charset.StandardCharsets.UTF_8;

/** Unit tests for TransactionSender static response helpers (no network required). */
public final class TransactionSenderTest {

    public static void main(String[] args) {
        int failed = 0;
        failed += run("isSubscriptionRequired true for SUBSCRIPTION_REQUIRED body",
                TransactionSenderTest::isSubscriptionRequired_true);
        failed += run("isSubscriptionRequired false for OFFLINE_LIMIT_EXCEEDED body",
                TransactionSenderTest::isSubscriptionRequired_false);
        failed += run("displayMessage returns error_message from SUBSCRIPTION_REQUIRED body",
                TransactionSenderTest::displayMessage_subscriptionRequired);
        System.out.printf("%d passed, %d failed%n", 3 - failed, failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    static void isSubscriptionRequired_true() {
        TransactionSender.Response r = response(422,
                "{\"error_code\":\"SUBSCRIPTION_REQUIRED\",\"error_message\":\"Subscription required\","
                + "\"error_category\":\"HARD_DECLINE\",\"retryable\":false}");
        ChaosTest.check(TransactionSender.isSubscriptionRequired(r), "expected true for SUBSCRIPTION_REQUIRED");
    }

    static void isSubscriptionRequired_false() {
        TransactionSender.Response r = response(422,
                "{\"error_code\":\"OFFLINE_LIMIT_EXCEEDED\",\"error_message\":\"limit reached\","
                + "\"error_category\":\"HARD_DECLINE\",\"retryable\":false}");
        ChaosTest.check(!TransactionSender.isSubscriptionRequired(r), "expected false for OFFLINE_LIMIT_EXCEEDED");
    }

    static void displayMessage_subscriptionRequired() {
        TransactionSender.Response r = response(422,
                "{\"error_code\":\"SUBSCRIPTION_REQUIRED\",\"error_message\":\"Subscription required\","
                + "\"error_category\":\"HARD_DECLINE\",\"retryable\":false}");
        ChaosTest.check("Subscription required".equals(TransactionSender.displayMessage(r)),
                "expected \"Subscription required\", got: " + TransactionSender.displayMessage(r));
    }

    private static TransactionSender.Response response(int status, String json) {
        return new TransactionSender.Response(status, json.getBytes(UTF_8), null, "test");
    }

    private static int run(String name, Runnable test) {
        try {
            test.run();
            System.out.printf("PASS %s%n", name);
            return 0;
        } catch (Throwable e) {
            System.out.printf("FAIL %s%n     %s%n", name, e);
            return 1;
        }
    }
}
