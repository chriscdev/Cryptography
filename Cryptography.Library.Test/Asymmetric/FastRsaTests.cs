using Cryptography.Library.Interfaces;
using Cryptography.Library.Symmetric;
using Cryptography.Library.Test.Factories;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());

      var cipher = fastRsa.Encrypt(data);

      var actual = fastRsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_SameInstanceAndPrivateKeyAndAesKeyAndIV_Should_UseFastPathAndGetOriginalString(string data)
    {
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q=");

      var cipher = fastRsa.Encrypt(data);

      var actual = fastRsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }        

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD")]
    public void Encrypt_Given_DifferentInstancesUsing1024BitPrivateKey_With_EncryptedKeyAndIV_Should_GetCipher(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q=");

      var actual = fastRsaEncrypt.Encrypt(data);

      Assert.Equal(cipher, actual);
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w== WF8VDqTz78fzl/A5rJwUfKScy4X0+0aCqiuisFqLf8bifYeOMPHRdeCbWm+gB362")]
    public void Encrypt_Given_DifferentInstancesUsing2048BitPrivateKey_With_EncryptedKeyAndIV_Should_GetCipher(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create2048BitPrivateKey(), "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w==");

      var actual = fastRsaEncrypt.Encrypt(data);

      Assert.Equal(cipher, actual);
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD")]
    public void Decrypt_Given_DifferentInstancesUsing1024BitPrivateKey_With_EncryptedKeyAndIV_Should_GetData(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q=");

      var actual = fastRsaEncrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w== WF8VDqTz78fzl/A5rJwUfKScy4X0+0aCqiuisFqLf8bifYeOMPHRdeCbWm+gB362")]
    public void Decrypt_Given_DifferentInstancesUsing2048BitPrivateKey_With_EncryptedKeyAndIV_Should_GetData(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create2048BitPrivateKey(), "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w==");

      var actual = fastRsaEncrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("Hello world")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_Then_Decrypt_Given_DifferentInstancesUsingPublicToEncryptAndPrivateKeyToDecrypt_Should_GetOriginalString(string data)
    {
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPublicKey());

      var cipher = fastRsaEncrypt.Encrypt(data);

      var fastRsaDecrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());

      var actual = fastRsaDecrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Fact]
    public void Encrypt_Then_Decrypt_Given_ServiceCollection()
    {
      var data = "The quick brown fox jumps over the lazy dog";

      var serviceCollection = new ServiceCollection();
      serviceCollection.AddSingleton<ICryptographyAlgorithm, FastRsa>(_ => new FastRsa(RsaKeyFactory.Create1024BitPrivateKey()));
      var provider = serviceCollection.BuildServiceProvider();

      var fastRsa = provider.GetService<ICryptographyAlgorithm>();

      var cipher = fastRsa.Encrypt(data);

      var actual = fastRsa.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Fact]
    public void Encrypt_ThreadSafety()
    {
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());
      var tasks = new List<Task>();
      var cancellationSource = new CancellationTokenSource(10000);
      for (var i = 0; i < 100; i++)
      {
        tasks.Add(Task.Run(() =>
        {
          while (!cancellationSource.IsCancellationRequested)
          {
            fastRsa.Encrypt("The quick brown fox jumps over the lazy dog");
          }
        }));
      }

      Task.WaitAll(tasks.ToArray());
    }

    [Fact]
    public void Encrypt_Then_Decrypt_ThreadSafety()
    {
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());
      var tasks = new List<Task>();
      var cancellationSource = new CancellationTokenSource(10000);
      for (var i = 0; i < 100; i++)
      {
        var inner = i;
        tasks.Add(Task.Run(() =>
        {
          while (!cancellationSource.IsCancellationRequested)
          {
            var cipher = fastRsa.Encrypt("The quick brown fox jumps over the lazy dog");
            fastRsa.Decrypt(cipher);
          }
        }));
      }

      Task.WaitAll(tasks.ToArray());
    }
  }
}
