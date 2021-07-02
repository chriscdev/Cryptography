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
    
    /// <summary>
    /// Gets the RSA encrypted AES Key and IV that will be appended to the messages. This value can only be set via the constructor.
    /// </summary>
    public string EncryptedKeyAndIV { get; }

    /// <summary>
    /// Constructor which will create a new key, IV and encrypt it. You can also pass in existing values for the arguments if you want to reuse accross instances or sessions.
    /// Note: If you want to reuse encrypedKeyAndIV then make sure you also use the AES Key and IV that was used to generate the cipher.
    /// </summary>
    /// <param name="rsaKeyXml">Key XML exported by using ToXMLString(). Public key can only encrypt but private key can encrypt and decrypt.</param>
    /// <param name="encrypedKeyAndIV">Optional. Set the EncryptedKeyAndIV, this is used if you stored the encryptedKeyAndIV and want to reuse the same AES Key and IV in subsequent encrypt/decrypt. Leave null to generate it. (recommended)</param>
    public FastRsa(string rsaKeyXml, string encrypedKeyAndIV = null)
    {
      var internalAes = new AesCryptoServiceProvider();
          
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

      (string key, string iv) = DecryptKeyCipher(cipherParts[0]);
    
      using var aesDecrypt = new Aes(Convert.FromBase64String(key), Convert.FromBase64String(iv));
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
  }
}
