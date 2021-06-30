using Cryptography.Library.Symmetric;
using Xunit;

namespace Cryptography.Library.Test.Symmetric
{
  public class AesTests
  {
    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_SameInstance_Should_GetOriginalString(string data)
    {
      var aes = new Aes();

      var cipher = aes.Encrypt(data);

      var actual = aes.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_DifferentInstancesWithSameKeyAndIV_Should_GetOriginalString(string data)
    {
      var commonAes = System.Security.Cryptography.Aes.Create();

      var aesEncrypt = new Aes(commonAes.Key, commonAes.IV);

      var cipher = aesEncrypt.Encrypt(data);

      var aesDecrypt = new Aes(commonAes.Key, commonAes.IV);

      var actual = aesDecrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }
  }
}
