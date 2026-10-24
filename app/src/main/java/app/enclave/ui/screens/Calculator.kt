package app.enclave.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.enclave.vault.PlainPrefs
import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode

/** A real, working calculator. Typing the secret code and pressing "=" opens the vault's lock screen. */
@Composable
fun CalculatorScreen(onSecret: () -> Unit) {
    var expr by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }

    fun press(k: String) {
        when (k) {
            "C" -> { expr = ""; result = "" }
            "⌫" -> expr = expr.dropLast(1)
            "=" -> {
                if (expr.isNotEmpty() && expr.all { it.isDigit() } && PlainPrefs.checkCalculatorCode(expr)) {
                    expr = ""; result = ""
                    onSecret()
                    return
                }
                result = evaluate(expr) ?: "Error"
                if (result != "Error") expr = result
            }
            "%" -> evaluate(expr)?.let { expr = BigDecimal(it).divide(BigDecimal(100)).stripTrailingZeros().toPlainString() }
            else -> {
                if (k in OPS && (expr.isEmpty() || expr.last() in OPS.joinToString(""))) {
                    if (expr.isNotEmpty()) expr = expr.dropLast(1) + k
                } else expr += k
            }
        }
        if (k != "=") result = evaluate(expr)?.takeIf { expr.any { c -> c.toString() in OPS } } ?: ""
    }

    val rows = listOf(
        listOf("C", "⌫", "%", "÷"),
        listOf("7", "8", "9", "×"),
        listOf("4", "5", "6", "−"),
        listOf("1", "2", "3", "+"),
        listOf("00", "0", ".", "="),
    )
    Column(Modifier.fillMaxSize().systemBarsPadding().padding(16.dp)) {
        Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.BottomEnd) {
            Column(horizontalAlignment = Alignment.End) {
                Text(expr.ifEmpty { "0" }, fontSize = 44.sp, textAlign = TextAlign.End, maxLines = 2)
                Text(result, fontSize = 24.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        rows.forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                row.forEach { k ->
                    val accent = k in OPS || k == "="
                    Button(
                        onClick = { press(k) },
                        shape = CircleShape,
                        modifier = Modifier.weight(1f).aspectRatio(1f).padding(vertical = 5.dp),
                        colors = if (accent) ButtonDefaults.buttonColors()
                        else ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    ) { Text(k, fontSize = 24.sp) }
                }
            }
        }
    }
}

private val OPS = listOf("+", "−", "×", "÷")

/** Evaluates "12+3×4" with normal precedence. Returns null if incomplete or invalid. */
private fun evaluate(expr: String): String? {
    if (expr.isEmpty()) return null
    val nums = mutableListOf<BigDecimal>()
    val ops = mutableListOf<Char>()
    val cur = StringBuilder()
    for (c in expr) {
        if (c.toString() in OPS) {
            nums += cur.toString().toBigDecimalOrNull() ?: return null
            ops += c; cur.clear()
        } else cur.append(c)
    }
    nums += cur.toString().toBigDecimalOrNull() ?: return null
    val mc = MathContext(16, RoundingMode.HALF_UP)
    // × and ÷ first
    var i = 0
    while (i < ops.size) {
        if (ops[i] == '×' || ops[i] == '÷') {
            val r = if (ops[i] == '×') nums[i].multiply(nums[i + 1], mc)
            else if (nums[i + 1].signum() == 0) return null else nums[i].divide(nums[i + 1], mc)
            nums[i] = r; nums.removeAt(i + 1); ops.removeAt(i)
        } else i++
    }
    var acc = nums[0]
    ops.forEachIndexed { j, op -> acc = if (op == '+') acc.add(nums[j + 1], mc) else acc.subtract(nums[j + 1], mc) }
    return acc.stripTrailingZeros().toPlainString()
}
