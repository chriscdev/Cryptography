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

# Usage

Register it as either a singleton or a scoped service on your favourite DI container. Below shows using the ServiceCollection:

```
serviceCollection.AddSingleton<ICryptographyAlgorithm, FastRsa>(_ => new FastRsa("<Public key>"));
```

FastRsa can then be injected into any class by using the ICryptographyAlgorithm interface for example:

```
public MyClass 
{
    public Myclass(ICryptographyAlgorithm cryptoAlgorithm)
    {
        //do your constructor logic
    }
}
```

Use Singleton or single instance of FastRsa if you require fast encryption and decryption. 

## Tips for fast encryption
Use a singleton or single instance of FastRsa. 

How this works is that it will encrypt the AES key and IV once, cache it and reuse it throughout the livetime of the FastRsa object. If you want a bit more security then dispose of the instance every X number of encryptions and create a new instance.

## Tips for fast decryption
In this document you will see the term fast path decryption. What this means is that if the cached encrypted AES key and IV matches that of the encrypted message then the FastRsa algorithm know that it was the encrypted using the current cached AES Key and IV and thus won't decrypt the key cipher but will use the current AES instance instead.

Follow these steps to setup the fast path decryption:
1. Create a RSA public and private key pair and save the public key in your config.
3. Create an instance of FastRsa.
4. Print out or debug your program to get the EncryptedKeyAndIV property value from the FastRsa instance.
5. Copy the value of EncryptedKeyAndIV to your config.
6. Construct an instance of FastRsa and pass in the EncryptedKeyAndIV eg. new FastRsa(privateKey, EncryptedKeyAndIV);

By storing and supplying the EncryptedKeyAndIV to the FastRsa instance enables it to decrypt the key cipher and get the AES key and IV. When a message needs to be decrypted it will check if the key cipher is the same as the cipher cached EncryptedKeyAndIV property and if it is then it does not need to decrypt it but can use AES Key and IV it decrypted ducring instantiation. So the fast path in essence is the elimination of the RSA decryption of the AES key and IV which is expensive.

Please note that this is only recommended if you require speed above anything else. You do 

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
|                 Method |       Mean |      Error |     StdDev |  Gen 0 | Gen 1 | Gen 2 | Allocated |
|----------------------- |-----------:|-----------:|-----------:|-------:|------:|------:|----------:|
|     RsaEncrypt_1024Bit |  16.313 μs |  0.3219 μs |  0.6930 μs | 0.1526 |     - |     - |     720 B |
|     RsaEncrypt_2048Bit |  36.836 μs |  0.6880 μs |  1.1305 μs | 0.2441 |     - |     - |   1,192 B |
|      AesEncrypt_256Bit |   2.188 μs |  0.0436 μs |  0.1110 μs | 1.5564 |     - |     - |   6,512 B |
| FastRsaEncrypt_1024Bit |   2.162 μs |  0.0424 μs |  0.0660 μs | 1.6747 |     - |     - |   7,008 B |
| FastRsaEncrypt_2048Bit |   2.237 μs |  0.0441 μs |  0.0573 μs | 1.7548 |     - |     - |   7,352 B |
|     RsaDecrypt_1024Bit | 127.922 μs |  2.3320 μs |  2.6856 μs |      - |     - |     - |     616 B |
|     RsaDecrypt_2048Bit | 659.140 μs | 13.0601 μs | 12.8268 μs |      - |     - |     - |     872 B |
|      AesDecrypt_256Bit |   2.475 μs |  0.0471 μs |  0.0579 μs | 1.0719 |     - |     - |   4,496 B |
| FastRsaDecrypt_1024Bit |   2.951 μs |  0.0455 μs |  0.0681 μs | 1.2054 |     - |     - |   5,056 B |
| FastRsaDecrypt_2048Bit |   3.065 μs |  0.0603 μs |  0.0804 μs | 1.2894 |     - |     - |   5,400 B |

FastRsa is extremely fast with encryption and rivals AES. 
By leveraging the fast path during decryption, FastRsa is comparable to AES.

# FastRsa Use-cases
Here are a few use-cases of the FastRsa algorithm.

## Securely logging of PII data
In this case you need to log PII data for possible troubleshooting but due to acts such as GDPR it can't be plaintext and access to it needs to be controlled. What better way than to encrypt it using FastRsa and a public key which is known by the system and then adding the private key to a key vault with limited access.

## Encrypting data for different recipients
If you have a system that needs to create sensitive messages that only the recipient is supposed to be able to read. This can be eitehr a person or another system, then your system would use the public key of the intended recipient and encrypt it. The recipient then know that the message is safe even if it was accidently sent to someone or something else or if there was a man-in-the-middle attack on your network.

## Encrypting and storing data on a possible unsafe or unsecured storage 
Sometimes you need to work with some shared infrastructure which a lot of people and systems have access to. A malicious actor either internal or external might be able to read sensitive data if a symmetric key is used. If the actor has access to the system that created the message, he/she would be able to decrypt the data. Therefore using FastRsa with a public key would protect your data because the malicious actor would need to their hands on the private key. 