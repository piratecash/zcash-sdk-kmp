package cash.p.zcash.demo

import androidx.compose.runtime.Composable
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.amount_zec
import org.jetbrains.compose.resources.stringResource

internal const val ZATOSHI_PER_ZEC: Long = 100_000_000L
private const val DECIMALS = 8

/** Parses a plain decimal ZEC amount. Returns null for anything a wallet must not send. */
internal fun parseZatoshi(text: String): Long? {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) return null

    val separator = trimmed.indexOf('.')
    val wholePart = if (separator < 0) trimmed else trimmed.substring(0, separator)
    val fractionPart = if (separator < 0) "" else trimmed.substring(separator + 1)
    if (fractionPart.length > DECIMALS) return null
    if (wholePart.isEmpty() && fractionPart.isEmpty()) return null
    if (!wholePart.all(Char::isDigit) || !fractionPart.all(Char::isDigit)) return null

    val whole = if (wholePart.isEmpty()) 0L else wholePart.toLongOrNull() ?: return null
    val fraction = fractionPart.padEnd(DECIMALS, '0').toLongOrNull() ?: return null
    if (whole > (Long.MAX_VALUE - fraction) / ZATOSHI_PER_ZEC) return null

    return whole * ZATOSHI_PER_ZEC + fraction
}

/** Fixed 8 decimals, no locale: the same string on every platform. */
internal fun formatZec(zatoshi: Long): String {
    val sign = if (zatoshi < 0) "-" else ""
    val magnitude = if (zatoshi < 0) -zatoshi else zatoshi
    val fraction = (magnitude % ZATOSHI_PER_ZEC).toString().padStart(DECIMALS, '0')
    return "$sign${magnitude / ZATOSHI_PER_ZEC}.$fraction"
}

/** The single place a zatoshi value becomes user-facing text. */
@Composable
internal fun zecAmount(zatoshi: Long): String = stringResource(Res.string.amount_zec, formatZec(zatoshi))
