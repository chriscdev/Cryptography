using Cryptography.Library.Configuration;
using Cryptography.Library.Enums;
using Cryptography.Library.Interfaces;
using Cryptography.Library.Symmetric;
using Cryptography.Library.Test.Factories;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
    public void Decrypt_Given_1024BitPrivateKey_With_EncryptedKeyAndIV_Should_GetOriginalData(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q=");

      var actual = fastRsaEncrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w== WF8VDqTz78fzl/A5rJwUfKScy4X0+0aCqiuisFqLf8bifYeOMPHRdeCbWm+gB362")]
    public void Decrypt_Given_2048BitPrivateKey_With_EncryptedKeyAndIV_Should_GetOriginalData(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create2048BitPrivateKey(), "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w==");

      var actual = fastRsaEncrypt.Decrypt(cipher);

      Assert.Equal(data, actual);
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD")]
    public void Decrypt_Given_MultipleDecryptRequests_With_CacheEnabled_Should_GetOriginalDataFasterWithSecondRun(string data, string cipher)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), true);

      var sw = Stopwatch.StartNew();
      var actualFirst = fastRsaEncrypt.Decrypt(cipher);
      var runtimeFirst = sw.ElapsedTicks;

      sw.Restart();
      var actualSecond = fastRsaEncrypt.Decrypt(cipher);
      var runtimeSecond = sw.ElapsedTicks;
      sw.Stop();

      Assert.Equal(data, actualFirst);
      Assert.Equal(data, actualSecond);
      Assert.True(runtimeFirst > runtimeSecond, "The second run wasn't faster than the first runs hence the cache was either not enabled or not working.");
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD")]
    public void Decrypt_Given_MultipleDecryptRequests_With_CacheEnabledAndCacheItemOptionsWithAbsoluteCacheExpiry_Should_GetOriginalDataFasterWithSecondRun(string data, string cipher)
    {
      var memCache = new MemoryCache(new MemoryCacheOptions());

      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), true, memCache, new CacheItemOptions(CacheExpiryType.Absolute, TimeSpan.FromSeconds(10)));

      var sw = Stopwatch.StartNew();
      var actualFirst = fastRsaEncrypt.Decrypt(cipher);
      var runtimeFirst = sw.ElapsedTicks;

      sw.Restart();
      var actualSecond = fastRsaEncrypt.Decrypt(cipher);
      var runtimeSecond = sw.ElapsedTicks;
      sw.Stop();

      Assert.Equal(data, actualFirst);
      Assert.Equal(data, actualSecond);
      Assert.True(runtimeFirst > runtimeSecond, "The second run wasn't faster than the first runs hence the cache was either not enabled or not working.");
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD")]
    public void Decrypt_Given_MultipleDecryptRequests_With_CacheEnabledAndCacheItemOptionsWithSlidingWindowCacheExpiry_Should_GetOriginalDataFasterWithSecondRun(string data, string cipher)
    {
      var memCache = new MemoryCache(new MemoryCacheOptions());

      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), true, memCache, new CacheItemOptions(CacheExpiryType.SlidingWindow, TimeSpan.FromSeconds(10)));

      var sw = Stopwatch.StartNew();
      var actualFirst = fastRsaEncrypt.Decrypt(cipher);
      var runtimeFirst = sw.ElapsedTicks;

      sw.Restart();
      var actualSecond = fastRsaEncrypt.Decrypt(cipher);
      var runtimeSecond = sw.ElapsedTicks;
      sw.Stop();

      Assert.Equal(data, actualFirst);
      Assert.Equal(data, actualSecond);
      Assert.True(runtimeFirst > runtimeSecond, "The second run wasn't faster than the first runs hence the cache was either not enabled or not working.");
    }

    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD", "WrFVNfy3pW7xFriwDLqte/MPSH4xN+Rxzo2XCcfZbTR/0rJtSaEDGhAlVUlsrv5ROrjssAHdc8nl3i4veL5Jwkr/XmD9B80/XW00tsno0+50ox9ReL5eYljBcUFw2whym4emShAcdgtqgD1umFKmLSdsNruyqHtrhZyG+BwyfQE= JNywqZgA8h6iStvt3EX79nXrgl/sl/SLppc8Gw2cQiQjkr6uJFCCBtKtgFaWG0aG")]
    public void Decrypt_Given_MultipleDecryptRequests_With_CacheEnabledAndDifferentKeys_Should_GetOriginalDataFasterWithSecondRun(string data, string cipher1, string cipher2)
    {
      // need to use the private key if you want to specify EncryptedKeyAndIV
      var fastRsaEncrypt = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), true);

      var sw = Stopwatch.StartNew();
      var actual1First = fastRsaEncrypt.Decrypt(cipher1);
      var runtime1First = sw.ElapsedTicks;

      sw.Restart();
      var actual1Second = fastRsaEncrypt.Decrypt(cipher1);
      var runtime1Second = sw.ElapsedTicks;
      sw.Stop();

      sw.Restart();
      var actual2First = fastRsaEncrypt.Decrypt(cipher2);
      var runtime2First = sw.ElapsedTicks;

      sw.Restart();
      var actual2Second = fastRsaEncrypt.Decrypt(cipher2);
      var runtime2Second = sw.ElapsedTicks;
      sw.Stop();

      Assert.Equal(data, actual1First);
      Assert.Equal(data, actual1Second);
      Assert.True(runtime1First > runtime1Second, "The second run wasn't faster than the first runs hence the cache was either not enabled or not working.");

      Assert.Equal(data, actual2First);
      Assert.Equal(data, actual2Second);
      Assert.True(runtime2First > runtime2Second, "The second run wasn't faster than the first runs hence the cache was either not enabled or not working.");
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
      ThreadPool.SetMinThreads(10, 10); // set the threadpool minimum to not wait for the hill climb alogirthm to spin up more threads.
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());
      var tasks = new List<Task>();
      var cancellationSource = new CancellationTokenSource(10000);

      for (var i = 0; i < 10; i++)
      {
        tasks.Add(Task.Run(() =>
        {
          while (!cancellationSource.IsCancellationRequested)
          {
            fastRsa.Encrypt("The quick brown fox jumps over the lazy dog");
          }
        }, cancellationSource.Token));
      }

      try
      {
        Task.WaitAll(tasks.ToArray());
      }
      catch (AggregateException aggEx)
      {
        //We expect a TaskCanceledException to be thrown if the task hasn't been scheduled it when cancellation happens, this can happen if system has limited resources expecially on build servers
        //If any other exception was thrown then fail the test
        Assert.True(aggEx.InnerExceptions.All(inner => inner is TaskCanceledException));
      }
    }

    [Fact]
    public void Decrypt_ThreadSafety()
    {
      ThreadPool.SetMinThreads(10, 10); // set the threadpool minimum to not wait for the hill climb alogirthm to spin up more threads.
      var fastRsa = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey());
      var tasks = new List<Task>();
      var cancellationSource = new CancellationTokenSource(10000);

      for (var i = 0; i < 10; i++)
      {
        var inner = i;
        tasks.Add(Task.Run(() =>
        {
          while (!cancellationSource.IsCancellationRequested)
          {
            fastRsa.Decrypt("gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD");
          }
        }, cancellationSource.Token));
      }

      try
      {
        Task.WaitAll(tasks.ToArray());
      }
      catch (AggregateException aggEx)
      {
        //We expect a TaskCanceledException to be thrown if the task hasn't been scheduled it when cancellation happens, this can happen if system has limited resources expecially on build servers
        //If any other exception was thrown then fail the test
        Assert.True(aggEx.InnerExceptions.All(inner => inner is TaskCanceledException));
      }
    }
  }
}
