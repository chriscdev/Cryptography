using Cryptography.Library.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Cryptography.Library.Symmetric
{
  public class Aes : ICryptographyAlgorithm
  {
    private readonly AesCryptoServiceProvider _aes;

    /// <summary>
    /// Constructor which will create a new key and IV
    /// </summary>
    public Aes()
    {
      _aes = new AesCryptoServiceProvider();
    }

    /// <summary>
    /// Constructor which will take an Aes instance
    /// </summary>
    public Aes(AesCryptoServiceProvider aes)
    {
      _aes = aes;
    }

    /// <summary>
    /// Constructor which sets the key and IV
    /// </summary>
    /// <param name="key"></param>
    /// <param name="iv"></param>
    public Aes(byte[] key, byte[] iv) : this()
    {
      _aes.Key = key;
      _aes.IV = iv;
    }

    ///<inheritdoc/>
    public string Encrypt(string data)
    {
      using ICryptoTransform encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV);

      using (var msEncrypt = new MemoryStream())
      {
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
          using (var swEncrypt = new StreamWriter(csEncrypt))
          {
            //Write all data to the stream
            swEncrypt.Write(data);
          }

          return Convert.ToBase64String(msEncrypt.ToArray());
        }
      }
    }

    ///<inheritdoc/>
    public string Decrypt(string cipher)
    {
      using ICryptoTransform decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV);

      using (var msDecrypt = new MemoryStream(Convert.FromBase64String(cipher)))
      {
        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        {
          using (var srDecrypt = new StreamReader(csDecrypt))
          {
            //Write all data to the stream
            return srDecrypt.ReadToEnd();
          }
        }
      }
    }

    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
      _aes?.Dispose();
    }
  }
}
