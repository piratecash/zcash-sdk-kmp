package cash.p.zcash

/** Every failure raised on the native side reaches the caller as this. */
public class ZcashException(
    message: String,
    cause: Throwable? = null,
    public val stage: SyncStage? = null,
) : Exception(message, cause) {
    /** A best-effort guess from the native message. Order matters: "connect timed out" is a timeout. */
    public val category: FailureCategory
        get() {
            val detail = message.orEmpty().lowercase()
            fun mentions(vararg markers: String) = markers.any { it in detail }
            return when {
                mentions("tls", "handshake") -> FailureCategory.TLS
                mentions("timeout", "timed out", "deadline") -> FailureCategory.TIMEOUT
                mentions("eof", "connect", "network", "socket", "dns", "lookup", "resolve", "transport error") ->
                    FailureCategory.NETWORK
                mentions("sqlite", "database") -> FailureCategory.DATABASE
                else -> FailureCategory.OTHER
            }
        }
}

/** The step of a sync pass that failed. */
public enum class SyncStage { TARGET, SCAN, ACCOUNT_HEIGHT }

public enum class FailureCategory { TLS, TIMEOUT, NETWORK, DATABASE, OTHER }
