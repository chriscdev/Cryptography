using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Cryptography.Library.Symmetric;
using Cryptography.Library.Test.Factories;
using System;
using Xunit;

namespace Cryptography.Library.Test.Benchmarks
{
  [SimpleJob]
  [MemoryDiagnoser]
  public class AlgorithmBenchmarks
  {
    private Rsa _rsa = new Rsa(RsaKeyFactory.Create1024PrivateKey());
    private Aes _aes = new Aes(Convert.FromBase64String("LH69rYyuaO5mWYj+daDXRY46x9ta0JFhTUWXT5HYumA="), Convert.FromBase64String("wlF5jKFqVcH6IaXiVahYOQ=="));
    private FastRsa _fastRsa = new FastRsa(RsaKeyFactory.Create1024PrivateKey());
    private FastRsa _fastRsa_UsingDecryptFastPath = new FastRsa(RsaKeyFactory.Create1024PrivateKey(), Convert.FromBase64String("LH69rYyuaO5mWYj+daDXRY46x9ta0JFhTUWXT5HYumA="), Convert.FromBase64String("wlF5jKFqVcH6IaXiVahYOQ=="));

    const string _shortString = "The quick brown fox jumps over the lazy dog";
    const string _rsaShortCipher = "qg9+JFJwBxb5HVcnplymlSdU0imuCOClzoD/XR3BGPZvSoE41GABxntBss212DZNafTBmQLTvXdvuXbEf9+yKr1a5mrkFyvs8NEmxqCW0Zea6FEvcOSsXQjl9FZbdXbf5rFkjoDMU52PKfl+i0m189TUtsfJDTi1Zuv7wuY2egM=";
    const string _aesShortCipher = "RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD";
    const string _fastRsaShortCipher = "ZPMMIhwpUZA2dXKWFRMTAqZwrGStD9IGfkM76dIwxR7RSGgK8RlshX4auAhaYoJiCBGqGB00u0Hv+/UNfWYSwknc01oU2VvraAZmSh3u/us9Wkx9jieTOSqwGeQuT+XFLm/YWymfpEKyklEJ2ttcSfMOuGxjhnwvsTj2F8JewHY= kHhXaGqgLqW6lKXDydTmcmpwVZ6n9B8l6bQYJS78mZsj3KxHzhyryY4Yj7jOc6fy";
    const string _fastRsaFastPathShortCipher = "eot0YIXjlmGxTyF+Yd0Ts9W3CF8QAVhI06vQGJllLeTDbmawqkDVy/+Eeq8kqo7nkZtN0muucSRcH0pRj0A+iIDHYIXLRxA8Jre7zhSSbgvmPf4LqEIb0AH7NuqewTW2feyv3Y2zKTpbJ7Z+FCCB7z3rJVZKtM3SDkNIBWUDWx0= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD";

    [Fact]
    public void StartBenchmark()
    {
      BenchmarkRunner.Run<AlgorithmBenchmarks>();
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [Benchmark]
    public string RsaEncrypt() => _rsa.Encrypt(_shortString);

    [Benchmark]
    public string AesEncrypt() => _aes.Encrypt(_shortString);

    [Benchmark]
    public string FastRsaEncrypt() => _fastRsa.Encrypt(_shortString);

    [Benchmark]
    public string RsaDecrypt() => _rsa.Decrypt(_rsaShortCipher);

    [Benchmark]
    public string AesDecrypt() => _aes.Decrypt(_aesShortCipher);

    [Benchmark]
    public string FastRsaDecrypt() => _fastRsa.Decrypt(_fastRsaShortCipher);

    [Benchmark]
    public string FastRsaDecrypt_UsingFastPath() => _fastRsa_UsingDecryptFastPath.Decrypt(_fastRsaFastPathShortCipher);
  }
}
