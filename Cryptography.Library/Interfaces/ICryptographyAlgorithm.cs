using System;

namespace Cryptography.Library.Interfaces
{
  public interface ICryptographyAlgorithm : IDisposable
  {
    /// <summary>
    /// Encrypt data string
    /// </summary>
    /// <param name="data">String to encrypt</param>
    /// <returns>Encrypted cipher</returns>
    string Encrypt(string data);

    /// <summary>
    /// Decrypt string cupher
    /// </summary>
    /// <param name="cipher">Encrypted cipher</param>
    /// <returns>Decrypted data string</returns>
    string Decrypt(string cipher);
  }
}
