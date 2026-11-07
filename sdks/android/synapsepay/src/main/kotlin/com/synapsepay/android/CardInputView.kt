package com.synapsepay.android

import android.content.Context
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.util.AttributeSet
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import java.util.Calendar

/**
 * Card number, expiry and CVV fields with formatting and the same checks as the web card frame. Use it in
 * layouts like any view; pass it to [SynapsePay.confirmCardPayment].
 *
 * The digits stay inside this view until they're encrypted for one confirm and wiped; autofill and screenshots
 * of the fields are blocked.
 */
class CardInputView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) :
    LinearLayout(context, attrs) {

    /** Called whenever completeness or the detected brand changes. Never receives digits. */
    var onChange: ((complete: Boolean, brand: String?) -> Unit)? = null

    private val number = field("Card number", 23)
    private val expiry = field("MM / YY", 7)
    private val cvc = field("CVV", 4)
    private val error = TextView(context)

    init {
        orientation = VERTICAL
        addView(number)
        addView(LinearLayout(context).apply {
            orientation = HORIZONTAL
            addView(expiry, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
            addView(cvc, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
        })
        addView(error)
        number.addTextChangedListener(formatter { d -> d.chunked(4).joinToString(" ") })
        expiry.addTextChangedListener(formatter { d -> if (d.length > 2) "${d.take(2)} / ${d.drop(2).take(2)}" else d })
        cvc.addTextChangedListener(formatter { d -> d.take(4) })
    }

    private fun field(hint: String, max: Int) = EditText(context).apply {
        this.hint = hint
        inputType = InputType.TYPE_CLASS_NUMBER
        filters = arrayOf(InputFilter.LengthFilter(max))
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        isSaveEnabled = false // never written into saved instance state
    }

    private fun formatter(format: (String) -> String) = object : TextWatcher {
        private var editing = false
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: Editable) {
            if (editing) return
            editing = true
            val formatted = format(CardValidation.digits(s))
            if (formatted != s.toString()) s.replace(0, s.length, formatted)
            editing = false
            error.text = ""
            onChange?.invoke(problem() == null, CardValidation.brand(CardValidation.digits(number.text)))
        }
    }

    /** Why the card can't be submitted yet, or null. Shown under the fields. */
    fun problem(): String? = CardValidation.problem(CardValidation.digits(number.text), CardValidation.digits(expiry.text),
                                                    CardValidation.digits(cvc.text), Calendar.getInstance())

    internal fun takeCard(): CardDetails? {
        problem()?.let { error.text = it; return null }
        val pan = CardValidation.digits(number.text)
        val exp = CardValidation.digits(expiry.text)
        val details = CardDetails(pan, "${exp.take(2)}/${exp.drop(2)}", CardValidation.digits(cvc.text),
                                  CardValidation.brand(pan)!!)
        cvc.text.clear() // never kept after an attempt
        return details
    }

    fun clear() {
        number.text.clear(); expiry.text.clear(); cvc.text.clear()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        // Keeps the fields out of screenshots and the recent-apps thumbnail.
        (context as? android.app.Activity)?.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
    }
}
