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
    private Rsa _rsa1024 = new Rsa(RsaKeyFactory.Create1024BitPrivateKey());
    private Rsa _rsa2048 = new Rsa(RsaKeyFactory.Create2048BitPrivateKey());
    private Aes _aes = new Aes(Convert.FromBase64String("LH69rYyuaO5mWYj+daDXRY46x9ta0JFhTUWXT5HYumA="), Convert.FromBase64String("wlF5jKFqVcH6IaXiVahYOQ=="));
    private FastRsa _fastRsa1024 = new FastRsa(RsaKeyFactory.Create1024BitPrivateKey(), "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q=");
    private FastRsa _fastRsa2048 = new FastRsa(RsaKeyFactory.Create2048BitPrivateKey(), "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w==");

    const string _shortString = "The quick brown fox jumps over the lazy dog";
    const string _aesShortCipher = "RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD";
    const string _rsa1024BitShortCipher = "qg9+JFJwBxb5HVcnplymlSdU0imuCOClzoD/XR3BGPZvSoE41GABxntBss212DZNafTBmQLTvXdvuXbEf9+yKr1a5mrkFyvs8NEmxqCW0Zea6FEvcOSsXQjl9FZbdXbf5rFkjoDMU52PKfl+i0m189TUtsfJDTi1Zuv7wuY2egM=";   
    const string _fastRsa1024BitShortCipher = "gfRvtMnf9ZklJJ1u6opDwqN2Psh1NULbZAZ7DsBVAlns6T7rEs1OFG0wvHwUfjbZoH4Nnz6LDjJoXwoi2+7COaRpFnWHdQf0S0jA4ZOdYibgi9opPB8y2sXENOKDyVhsAiVZOp9PiaeKRiiLiXcFaJtrw4gJvecEObbUwbfSe3Q= RhGctD8s9Lx/t2bPeg6qz6CtBwc4nk7gulXnFoROuLMTS98SlFP14BcvL9Lm/3tD";
    const string _rsa2048BitShortCipher = "XGkuFtJAUM7LhbvTb6k57J5BPvry8bpR3S2pJOlIahlpZK5lqjdH4iB1tfKOIbRW3aY8qsuwUPV7r53sRlZ7XU4dVlNYsMaGZroP9iVuirXp4vfE3hbDm7bJktuqxWK6B7urHSJzYFxmm2Jd4CCCTpuZGfGXN9rHmf23UKiu0PjX71oKOVuH6j4A2lXtmMIVL346ANHPp5QIOydFA4hqu4ZEGupxa/VLhJxnGFanFG5crs8oWEPYMx0QweVzLjim27UcS+198WW1joFFuDSu7a4kI0Nm0LDcBc5pb2W6BNclKWZ0mcThpUo/DoOGeSiq761RtFXdxA6Eclk8sG4+VQ==";
    const string _fastRsa2048BitShortCipher = "IaY4+mLytwlVRNW1e5lxKmDSrQ0DSYNEt7NSdw1faafBpDI0H3xM64TQVAz85ZJMhYz3RgmDs2WU7WYE4DxZkj2eQP8oe6OgEafSTlQMMEuc7HfRysPxeiXqAOC5E/fJp62O5LSuhs4nMNt/0YeS3K30VhAN90IaqvM7OuB2evTbEJB0Yz0w3am7aFHzJjF7Ma9L7f2k0F3j5QzQpRifhTmnGaD+ngrO0Ss2HQsgO5v64UohcJ0Q9OzupnIG1UWpeCwH+dqOw0lXhG9JEBDIbc85c/Ot6K9YNSGL8v2SErLMexIcfIXIX/HBrEKDrmcZJux4hbVGvZpmv6z+cFuT1w== WF8VDqTz78fzl/A5rJwUfKScy4X0+0aCqiuisFqLf8bifYeOMPHRdeCbWm+gB362";

    //[Fact]
    public void StartBenchmark()
    {
      BenchmarkRunner.Run<AlgorithmBenchmarks>();
    }

    [Benchmark]
    public string RsaEncrypt_1024Bit() => _rsa1024.Encrypt(_shortString);

    [Benchmark]
    public string RsaEncrypt_2048Bit() => _rsa2048.Encrypt(_shortString);

    [Benchmark]
    public string AesEncrypt_256Bit() => _aes.Encrypt(_shortString);

    [Benchmark]
    public string FastRsaEncrypt_1024Bit() => _fastRsa1024.Encrypt(_shortString);

    [Benchmark]
    public string FastRsaEncrypt_2048Bit() => _fastRsa2048.Encrypt(_shortString);

    [Benchmark]
    public string RsaDecrypt_1024Bit() => _rsa1024.Decrypt(_rsa1024BitShortCipher);

    [Benchmark]
    public string RsaDecrypt_2048Bit() => _rsa2048.Decrypt(_rsa2048BitShortCipher);

    [Benchmark]
    public string AesDecrypt_256Bit() => _aes.Decrypt(_aesShortCipher);

    [Benchmark]
    public string FastRsaDecrypt_1024Bit() => _fastRsa1024.Decrypt(_fastRsa1024BitShortCipher);

    [Benchmark]
    public string FastRsaDecrypt_2048Bit() => _fastRsa2048.Decrypt(_fastRsa2048BitShortCipher);
  }
}
