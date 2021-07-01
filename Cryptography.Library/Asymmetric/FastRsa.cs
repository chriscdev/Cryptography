using Cryptography.Library.Interfaces;
using System;
using System.Security.Cryptography;

namespace Cryptography.Library.Symmetric
{
  /// <summary>
  /// Fast RSA can be used to encrypt large blobs of data.
  /// It uses the AES symmetric encryption algorithm to encrypt the data and then the key and IV is encrypted using RSA.
  /// This algorithm combines the speed of AES with the public/private key of RSA.
  /// The intended use of this algorithm is when you want to encrypt large blobs of data but want to have a private key that is stored in a secure place for decryption.
  /// Please note: For high performance, use this class as a singleton which will use the same encrypted key and IV for the entire process. It will reset when the webserver refreshes or restarts.
  /// </summary>
  public class FastRsa : ICryptographyAlgorithm
  {
    private readonly Aes _aesEncrypt;
    private readonly Rsa _rsa;
    private readonly string _encryptedKeyAndIV;

    /// <summary>
    /// Constructor which will create a new key and IV
    /// </summary>
    /// <param name="rsaKeyXml">Key XML exported by using ToXMLString(). Public key can only encrypt but private key can encrypt and decrypt.</param>
    /// <param name="aesKey">Optional. Set the AES key, leave null to generate a new key (recommended)/</param>
    /// <param name="aesIV">Optional. Set the AES IV, leave null to generate a new IV (recommended)/</param></param>
    public FastRsa(string rsaKeyXml, byte[] aesKey = null, byte[] aesIV = null)
    {
      var internalAes = new AesCryptoServiceProvider();
      
      if (aesKey != null && aesKey.Length > 0)
        internalAes.Key = aesKey;

      if (aesIV != null && aesIV.Length > 0)
        internalAes.IV = aesIV;

      _aesEncrypt = new Aes(internalAes);
      _rsa = new Rsa(rsaKeyXml);
      _encryptedKeyAndIV = _rsa.Encrypt($"{Convert.ToBase64String(internalAes.Key)} {Convert.ToBase64String(internalAes.IV)}");
    }

    ///<inheritdoc/>
    public string Encrypt(string data)
    {
      return $"{_encryptedKeyAndIV} {_aesEncrypt.Encrypt(data)}";
    }

    ///<inheritdoc/>
    public string Decrypt(string cipher)
    {
      var cipherParts = cipher.Split(" ");

      if (cipherParts.Length != 2)
        throw new ArgumentException("Not a valid FastRsa cipher, missing symmetric key and IV cipher.", nameof(cipher));

      var keyAndIv = _rsa.Decrypt(cipherParts[0]).Split(" ");

      if (keyAndIv.Length != 2)
        throw new ArgumentException("Not a valid FastRsa cipher, missing key and/or IV in symmetric key and IV cipher.", nameof(cipher));

      //Fast path: If the current encrypted key and IV are the same as the one in the cipher then use the current _aesEncrypt instance, no need to create a new one.
      if (_encryptedKeyAndIV == cipherParts[0])
        return _aesEncrypt.Decrypt(cipherParts[1]);

      using var aesDecrypt = new Aes(Convert.FromBase64String(keyAndIv[0]), Convert.FromBase64String(keyAndIv[1]));
      return aesDecrypt.Decrypt(cipherParts[1]);
    }

    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
      _rsa?.Dispose();
      _aesEncrypt?.Dispose();
    }
  }
}
