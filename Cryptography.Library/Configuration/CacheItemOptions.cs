using Cryptography.Library.Enums;
using System;

namespace Cryptography.Library.Configuration
{
  /// <summary>
  /// Options for cached items
  /// </summary>
  public class CacheItemOptions
  {
    /// <summary>
    /// Cache expiry type
    /// </summary>
    public CacheExpiryType CacheExpiryType { get; set; }

    /// <summary>
    /// Expiry time that will be used in conjuction with the <see cref="CacheExpiryType"/>
    /// </summary>
    public TimeSpan ExpiryTime { get; set; }

    /// <summary>
    /// Constructor to set the 
    /// </summary>
    /// <param name="cacheExpiryType">Cache expiry type <see cref="CacheExpiryType"/></param>
    /// <param name="expiryTime">Expiry time</param>
    public CacheItemOptions(CacheExpiryType cacheExpiryType, TimeSpan expiryTime)
    {
      CacheExpiryType = cacheExpiryType;
      ExpiryTime = expiryTime;
    }
  }
}
