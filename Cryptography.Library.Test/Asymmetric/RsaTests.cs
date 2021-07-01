using Cryptography.Library.Symmetric;
using Cryptography.Library.Test.Factories;
using System.Security.Cryptography;
using Xunit;

namespace Cryptography.Library.Test.Asymmetric
{
  public class RsaTests
  {
    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_SameInstanceAndPrivateKey_Should_GetOriginalString(string data)
    {
      var rsa = new Rsa(RsaKeyFactory.Create1024PrivateKey());

      var cipher = rsa.Encrypt(data);

      var actual = rsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }    

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_DifferentInstancesUsingPublicToEncryptAndPrivateKeyToDecrypt_Should_GetOriginalString(string data)
    {
      var rsaEncrypt = new Rsa(RsaKeyFactory.Create1024PublicKey());

      var cipher = rsaEncrypt.Encrypt(data);

      var rsaDecrypt = new Rsa(RsaKeyFactory.Create1024PrivateKey());

      var actual = rsaDecrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Fact]
    public void GeneratePrivateAndPublicKeyPair()
    {
      var rsa = new RSACryptoServiceProvider(2048);

      var privateKey = rsa.ToXmlString(true);
      var publicKey = rsa.ToXmlString(false);

      Assert.NotEmpty(privateKey);
      Assert.NotEmpty(publicKey);
    }
  }
}
