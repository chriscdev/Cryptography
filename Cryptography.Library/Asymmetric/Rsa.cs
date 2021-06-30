using Cryptography.Library.Interfaces;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.Library.Symmetric
{
  /// <summary>
  /// RSA is an asymetric encryption algorith which uses the .NET RSACryptoServiceProvider
  /// </summary>
  public class Rsa : ICryptographyAlgorithm
  {
    private readonly RSACryptoServiceProvider _rsa;

    /// <summary>
    /// Constructor which will create a new key and IV
    /// </summary>
    /// <param name="keyXml">Key XML exported by using ToXMLString(). Public key can only encrypt but private key can encrypt and decrypt.</param>
    public Rsa(string keyXml)
    {
      _rsa = new RSACryptoServiceProvider();
      _rsa.FromXmlString(keyXml);
    }

    ///<inheritdoc/>
    public string Encrypt(string data)
    {
      var byteConverter = new UTF8Encoding();

      //Encrypt the passed byte array and specify OAEP padding.  
      //OAEP padding is only available on Microsoft Windows XP or later.  
      return Convert.ToBase64String(_rsa.Encrypt(byteConverter.GetBytes(data), true));
    }

    ///<inheritdoc/>
    public string Decrypt(string cipher)
    {
      var byteConverter = new UTF8Encoding();

      //Decrypt the passed byte array and specify OAEP padding.  
      //OAEP padding is only available on Microsoft Windows XP or later.  
      return byteConverter.GetString(_rsa.Decrypt(Convert.FromBase64String(cipher), true));
    }

    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
      _rsa?.Dispose();
    }
  }
}
