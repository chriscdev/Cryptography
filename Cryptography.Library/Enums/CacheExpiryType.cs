namespace Cryptography.Library.Enums
{
  /// <summary>
  /// Cache expiry type
  /// </summary>
  public enum CacheExpiryType
  {
    /// <summary>
    /// Absolute expiry uses a fixed time to expire the cache whether it was accessed or not.
    /// </summary>
    Absolute,
    /// <summary>
    /// Sliding window uses the expiry time to expire the cache if the item wasn't accessed whithin that time.
    /// </summary>
    SlidingWindow
  }
}
