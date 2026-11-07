package com.synapsepay.android;

import java.util.Calendar;

/** Same rules as the web card frame, so customers see the same errors everywhere. */
public final class CardValidation {
    private CardValidation() {}

    public static String digits(CharSequence s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) if (Character.isDigit(s.charAt(i))) out.append(s.charAt(i));
        return out.toString();
    }

    /** VISA, MASTERCARD, AMEX, RUPAY, or null if not accepted. */
    public static String brand(String pan) {
        if (pan.startsWith("4")) return "VISA";
        if (pan.matches("^(5[1-5]|2(2[2-9]|[3-6]\\d|7[01]|720)).*")) return "MASTERCARD";
        if (pan.matches("^3[47].*")) return "AMEX";
        if (pan.matches("^(60|65|81|82|508|353|356).*")) return "RUPAY";
        return null;
    }

    public static boolean luhn(String pan) {
        int sum = 0;
        for (int i = 0; i < pan.length(); i++) {
            int d = pan.charAt(pan.length() - 1 - i) - '0';
            if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
        }
        return sum % 10 == 0;
    }

    /** null if the card can be submitted, else a message for the customer. `expiry` is "MMYY" digits. */
    public static String problem(String pan, String expiry, String cvc, Calendar now) {
        if (pan.length() < 13 || pan.length() > 19 || !luhn(pan)) return "Enter a valid card number.";
        String brand = brand(pan);
        if (brand == null) return "This card type isn't accepted.";
        if (expiry.length() != 4) return "Enter the expiry as MM / YY.";
        int month = Integer.parseInt(expiry.substring(0, 2)), year = 2000 + Integer.parseInt(expiry.substring(2));
        if (month < 1 || month > 12) return "Enter the expiry as MM / YY.";
        int thisYear = now.get(Calendar.YEAR), thisMonth = now.get(Calendar.MONTH) + 1;
        if (year < thisYear || (year == thisYear && month < thisMonth)) return "This card has expired.";
        int cvcLength = "AMEX".equals(brand) ? 4 : 3;
        if (cvc.length() != cvcLength) return "Enter the " + cvcLength + "-digit security code.";
        return null;
    }
}
