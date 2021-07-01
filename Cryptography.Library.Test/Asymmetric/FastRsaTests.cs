using Cryptography.Library.Symmetric;
using Cryptography.Library.Test.Factories;
using System;
using Xunit;

namespace Cryptography.Library.Test.Asymmetric
{
  public class FastRsaTests
  {
    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_SameInstanceAndPrivateKey_Should_GetOriginalString(string data)
    {
      var rsa = new FastRsa(RsaKeyFactory.Create1024PrivateKey());

      var cipher = rsa.Encrypt(data);

      var actual = rsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_SameInstanceAndPrivateKeyAndAesKeyAndIV_Should_GetOriginalString(string data)
    {
      var rsa = new FastRsa(RsaKeyFactory.Create1024PrivateKey(), Convert.FromBase64String("LH69rYyuaO5mWYj+daDXRY46x9ta0JFhTUWXT5HYumA="), Convert.FromBase64String("wlF5jKFqVcH6IaXiVahYOQ=="));

      var cipher = rsa.Encrypt(data);

      var actual = rsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_DifferentInstancesUsingPublicToEncryptAndPrivateKeyToDecrypt_Should_GetOriginalString(string data)
    {
      var rsaEncrypt = new FastRsa(RsaKeyFactory.Create1024PublicKey());

      var cipher = rsaEncrypt.Encrypt(data);

      var rsaDecrypt = new FastRsa(RsaKeyFactory.Create1024PrivateKey());

      var actual = rsaDecrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }
  }
}
