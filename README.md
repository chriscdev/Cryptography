# Cryptography
A .Net cryptography library to easily do symmetric and asymmetric encryption/decryption. It also includes a fast hybrid encryption algorithm which combines the strengths of both asymmetric and symmetric encryption.

# Introduction
This library was created primarily for the FastRsa encryption. The idea came about the need to have information encrypted with a public key that resided on an API and then later decrypted by another party which had the private key. Pretty much how the TLS protocol exchange the symmetric key but here there is no key exchange only a data exchange.

You probably asking: why don't you use RSA? Well the two biggest problems with RSA and asymmetric encryption in general is speed and the fact that it can't encryption large blobs of data. For this reason the FastRsa algorithm was created to leverage the best aspects of asymmetric and symmetric encryption. 

As part of the FastRsa implementation there is also an easy to use RSA and AES encryption classes.

# How does FastRsa work
For a lack of a better name I just called it FastRsa although it uses both RSA and AES encryption. 

## For encryption the following steps happen:
1. Encrypt the AES key and IV using RSA encryption.
2. Encrypt the data payload using AES encryption.
3. Concatenate the encrypted output of step 1 and 2 and that is the cipher.

## For decryption the following steps happen:
1. If the AES key and IV cipher matches the current internal cipher then use the fast path meaning it will use the current cached key and IV. Else decrypt the AES key and IV using RSA encryption.
2. Decrypt the data payload using AES encryption and the key and IV decrypted from step 1.

It is highly recommended to use the RSA public key for encryption and the private key for decryption and it goes without saying to store the private key in a safe place!

# How to generate a RSA public and private key pair
Use the following code to generate a public and private key pair:
```
var rsa = new RSACryptoServiceProvider(2048); //2048 is the keysize, the larger the key the better the strength.
var privateKey = rsa.ToXmlString(true);
var publicKey = rsa.ToXmlString(false);
```

# Benchmarks
```
BenchmarkDotNet=v0.13.0, OS=Windows 10.0.19041.1052 (2004/May2020Update/20H1)
Intel Core i7-6820HK CPU 2.70GHz (Skylake), 1 CPU, 8 logical and 4 physical cores
.NET SDK=5.0.300
  [Host]     : .NET 5.0.6 (5.0.621.22011), X64 RyuJIT
  DefaultJob : .NET 5.0.6 (5.0.621.22011), X64 RyuJIT

```
|                       Method |       Mean |     Error |     StdDev |     Median |  Gen 0 | Gen 1 | Gen 2 | Allocated |
|----------------------------- |-----------:|----------:|-----------:|-----------:|-------:|------:|------:|----------:|
|                   RsaEncrypt |  16.093 μs | 0.3156 μs |  0.3991 μs |  16.174 μs | 0.1526 |     - |     - |     720 B |
|                   AesEncrypt |   2.793 μs | 0.1617 μs |  0.4481 μs |   2.756 μs | 1.5564 |     - |     - |   6,512 B |
|               FastRsaEncrypt |   3.158 μs | 0.2226 μs |  0.6315 μs |   3.020 μs | 1.6708 |     - |     - |   7,008 B |
|                   RsaDecrypt | 147.029 μs | 5.4847 μs | 15.2893 μs | 142.048 μs |      - |     - |     - |     616 B |
|                   AesDecrypt |   2.903 μs | 0.1324 μs |  0.3778 μs |   2.795 μs | 1.0681 |     - |     - |   4,496 B |
|               FastRsaDecrypt | 141.403 μs | 2.5773 μs |  3.1651 μs | 141.150 μs | 1.4648 |     - |     - |   6,528 B |

FastRsa is extremely fast with encryption and rivals AES. 
The decryption is as slow as RSA but it has the added benefit of being able to encrypt/decrypt large data strings.

# FastRsa Use-cases
Here are a few use-cases of the FastRsa algorithm.

## Securely logging of PII data
## Encrypting data for different recipients
## Encrypting and storing data on a possible unsafe or unsecured storage 