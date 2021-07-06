using Cryptography.Library.Configuration;
using Cryptography.Library.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Security.Cryptography;

namespace Cryptography.Library.Symmetric
{
  /// <summary>
  /// Fast RSA can be used to encrypt large blobs of data.
  /// It uses the AES symmetric encryption algorithm to encrypt the data and then the key and IV is encrypted using RSA.
  /// This algorithm combines the speed of AES with the public/private key of RSA.
  /// The intended use of this algorithm is when you want to encrypt large blobs of data but want to have a private key that is stored in a secure place for decryption.
  /// For fast encryption performance use this class as a singleton which will use the same encrypted key and IV for the entire process. It will reset when the webserver refreshes or restarts.
  /// For fast decrption switch enable the keyCache (useKeyCache = true), to enable the cache to save the AES key and IV for faster subsequent decryption. Note that this will only work if there are groups of ciphers that were encrypted with the same AES key and IV.
  /// Important: You can only decrypt data that has been encrypted using this FastRsa class, it does not work with any other algorithms or libraries. Also make sure to use the same public and private key pair when encrypting and decrypting.
  /// </summary>
  public class FastRsa : ICryptographyAlgorithm
  {
    private readonly Aes _aesEncrypt;
    private readonly Rsa _rsa;
    private readonly bool _useKeyCache;
    private readonly MemoryCacheEntryOptions _memoryCacheEntryOptions;
    private static readonly MemoryCache _decryptedKeyCache = new(new MemoryCacheOptions());

    /// <summary>
    /// Gets the RSA encrypted AES Key and IV that will be appended to the messages. This value can only be set via the constructor.
    /// </summary>
    public string EncryptedKeyAndIV { get; }

    /// <summary>
    /// Constructor which will create a new key, IV and encrypt it. You can also pass in existing values for the arguments if you want to reuse accross instances or sessions.
    /// Note: If you want to reuse encrypedKeyAndIV then make sure you also use the AES Key and IV that was used to generate the cipher.
    /// </summary>
    /// <param name="rsaKeyXml">Key XML exported by using ToXMLString(). Public key can only encrypt but private key can encrypt and decrypt.</param>
    /// <param name="encrypedKeyAndIV">Optional. Set the EncryptedKeyAndIV, this is used if you stored the encryptedKeyAndIV and want to reuse the same AES Key and IV in subsequent encrypt/decrypt. Leave null to generate it (recommended).</param>
    /// <param name="useKeyCache">Optional. Enable the use of the key cache which will store all the decrypted key and IV for lookup and therefore faster decryption. Disable if you you are worried about consuming large amounts of memory (enabled by default).</param>
    /// <param name="keyCacheOptions">Optional. Options for the key cache, set the type of expiration and the epiry time. By using a good expiry strategy you will optimize memory usage and decryption performance. (keep null to use default)</param>
    public FastRsa(string rsaKeyXml, string encrypedKeyAndIV = null, bool useKeyCache = true, CacheItemOptions keyCacheOptions = null)
    {
      var internalAes = new AesCryptoServiceProvider();

      _useKeyCache = useKeyCache;
      _rsa = new Rsa(rsaKeyXml);

      if (string.IsNullOrWhiteSpace(encrypedKeyAndIV))
      {
        //Create new EncryptedKeyAndIV using a new AES key and IV
        EncryptedKeyAndIV = _rsa.Encrypt($"{Convert.ToBase64String(internalAes.Key)} {Convert.ToBase64String(internalAes.IV)}");
      }
      else
      {
        //Get the AES key and IV from the encrypedKeyAndIV
        EncryptedKeyAndIV = encrypedKeyAndIV;
        (string key, string iv) = DecryptKeyCipher(encrypedKeyAndIV);
        internalAes.Key = Convert.FromBase64String(key);
        internalAes.IV = Convert.FromBase64String(iv);
      }

      _aesEncrypt = new Aes(internalAes);

      if (keyCacheOptions != null)
      {
        _memoryCacheEntryOptions = new MemoryCacheEntryOptions();
        if (keyCacheOptions.CacheExpiryType == Enums.CacheExpiryType.Absolute)
          _memoryCacheEntryOptions.AbsoluteExpirationRelativeToNow = keyCacheOptions.ExpiryTime;
        else
          _memoryCacheEntryOptions.SlidingExpiration = keyCacheOptions.ExpiryTime;
      }
    }

    /// <summary>
    /// Constructor which will create a new key, IV and encrypt it. 
    /// Note: By setting useKeyCache to true will increase decrypt speed considerabily given that you decrypt groups of data that used the same AES key and IV.
    /// </summary>
    /// <param name="rsaKeyXml">Key XML exported by using ToXMLString(). Public key can only encrypt but private key can encrypt and decrypt.</param>
    /// <param name="useKeyCache">Enable the use of the key cache which will store all the decrypted key and IV for lookup and therefore faster decryption. Disable if you you are worried about consuming large amounts of memory.</param>
    /// <param name="keyCacheOptions">Optional. Options for the key cache, set the type of expiration and the epiry time. By using a good expiry strategy you will optimize memory usage and decryption performance (keep null to use default).</param>
    public FastRsa(string rsaKeyXml, bool useKeyCache, CacheItemOptions keyCacheOptions = null) : this(rsaKeyXml, null, useKeyCache, keyCacheOptions)
    {
    }

    ///<inheritdoc/>
    public string Encrypt(string data)
    {
      return $"{EncryptedKeyAndIV} {_aesEncrypt.Encrypt(data)}";
    }

    ///<inheritdoc/>
    public string Decrypt(string cipher)
    {
      var cipherParts = cipher.Split(" ");

      if (cipherParts.Length != 2)
        throw new ArgumentException("Not a valid FastRsa cipher, missing symmetric key and IV cipher.", nameof(cipher));

      //Fast path: If the current encrypted key and IV are the same as the one in the cipher then use the current _aesEncrypt instance, no need to create a new one.
      if (EncryptedKeyAndIV == cipherParts[0])
        return _aesEncrypt.Decrypt(cipherParts[1]);

      byte[] keyBytes;
      byte[] ivBytes;

      //Cache path: If the encrypted key and IV is the same as the cache key then use the AES key and IV from cache (not need to decrypt)
      if (_useKeyCache)
      {
        KeyCacheValue keyCacheValue = _decryptedKeyCache.GetOrCreate(cipherParts[0], (entry) =>
        {
          if (_memoryCacheEntryOptions != null)
            entry.SetOptions(_memoryCacheEntryOptions);

          (string key, string iv) = DecryptKeyCipher(cipherParts[0]);

          return new KeyCacheValue(Convert.FromBase64String(key), Convert.FromBase64String(iv));
        });

        keyBytes = keyCacheValue.Key;
        ivBytes = keyCacheValue.IV;
      }
      else
      {
        (string key, string iv) = DecryptKeyCipher(cipherParts[0]);

        keyBytes = Convert.FromBase64String(key);
        ivBytes = Convert.FromBase64String(iv);
      }

      using var aesDecrypt = new Aes(keyBytes, ivBytes);
      return aesDecrypt.Decrypt(cipherParts[1]);
    }

    private (string key, string iv) DecryptKeyCipher(string keyCipher)
    {
      var keyAndIv = _rsa.Decrypt(keyCipher).Split(" ");

      if (keyAndIv.Length != 2)
        throw new ArgumentException("Not a valid FastRsa cipher, missing key and/or IV in symmetric key and IV cipher.");

      return (keyAndIv[0], keyAndIv[1]);
    }

    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
      _rsa?.Dispose();
      _aesEncrypt?.Dispose();
    }

    /// <summary>
    /// Key cache value model
    /// </summary>
    private class KeyCacheValue
    {
      public byte[] Key { get; set; }
      public byte[] IV { get; set; }

      public KeyCacheValue(byte[] key, byte[] iv)
      {
        Key = key;
        IV = iv;
      }
    }
  }
}
