package cash.p.zcash

/** Every failure raised on the native side reaches the caller as this. */
public class ZcashException(message: String, cause: Throwable? = null) : Exception(message, cause)
