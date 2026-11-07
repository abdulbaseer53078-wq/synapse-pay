import com.synapsepay.android.CardValidation;
import com.synapsepay.android.CheckoutCrypto;
import com.synapsepay.android.SynapsePayApi;

import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Exercises the Android SDK's Java core on a plain JVM against a live backend (backend/tests runs it):
 *   java ConfirmMain <apiBase> <clientSecret> <pan> <MMYY> <cvc>
 * Prints the confirm response body.
 */
public class ConfirmMain {
    public static void main(String[] args) throws Exception {
        String pan = args[2], expiry = args[3], cvc = args[4];
        String problem = CardValidation.problem(pan, expiry, cvc, Calendar.getInstance());
        if (problem != null) throw new IllegalArgumentException(problem);
        SynapsePayApi api = new SynapsePayApi(args[0]);
        String jwk = api.checkoutKey().body;
        CheckoutCrypto crypto = new CheckoutCrypto(field(jwk, "x"), field(jwk, "y"));
        SynapsePayApi.Response r = api.confirm(args[1], crypto.seal(pan, "data"), crypto.seal(cvc, "cvv"),
                expiry.substring(0, 2) + "/" + expiry.substring(2), CardValidation.brand(pan));
        System.out.println(r.body);
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        if (!m.find()) throw new IllegalStateException("no " + name + " in checkout key");
        return m.group(1);
    }
}
