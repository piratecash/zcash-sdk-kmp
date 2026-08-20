package cash.p.zcash

/** Shielded pools and the transparent pool, in the bit order used by the native layer. */
public enum class Pool(internal val bit: Int) {
    TRANSPARENT(0),
    SAPLING(1),
    ORCHARD(2),
    IRONWOOD(3),
}

/**
 * A set of pools, carried to the native layer as a bitmask.
 *
 * Selecting the source pools of a spend is a first-class parameter here; the ECC SDK
 * could not express it at all.
 */
@JvmInline
public value class PoolSet(internal val mask: Int) {

    public operator fun contains(pool: Pool): Boolean = mask and (1 shl pool.bit) != 0

    public operator fun plus(pool: Pool): PoolSet = PoolSet(mask or (1 shl pool.bit))

    public operator fun minus(pool: Pool): PoolSet = PoolSet(mask and (1 shl pool.bit).inv())

    public val isEmpty: Boolean get() = mask == 0

    public fun toList(): List<Pool> = Pool.entries.filter { it in this }

    public companion object {
        public val NONE: PoolSet = PoolSet(0b0000)
        public val ALL: PoolSet = PoolSet(0b1111)
        public val SHIELDED: PoolSet = PoolSet(0b1110)

        public fun of(vararg pools: Pool): PoolSet =
            PoolSet(pools.fold(0) { acc, p -> acc or (1 shl p.bit) })
    }
}
