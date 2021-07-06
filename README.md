# Cryptography
A .Net cryptography library to easily do symmetric and asymmetric encryption/decryption. It also includes a fast hybrid encryption algorithm which combines the strengths of both asymmetric and symmetric encryption.

# Introduction
This library was created primarily for the FastRsa encryption. The idea came about the need to have information encrypted with a public key that resided on an API and then later decrypted by another party which had the private key. Pretty much how the TLS protocol exchange the symmetric key but here there is no key exchange only a data exchange.

You probably asking: why don't you use RSA? Well the two biggest problems with RSA and asymmetric encryption in general is speed and the fact that it can't encrypt large blobs of data. For this reason the FastRsa algorithm was created to leverage the best aspects of asymmetric and symmetric encryption. 

As part of the FastRsa implementation there is also an easy to use RSA and AES encryption classes.

# How does FastRsa work
For a lack of a better name I just called it FastRsa although it uses both RSA and AES encryption. In a nutshell it uses AES to encrypt the data and then use RSA encryption to encrypt the AES key and IV which is then added as part of the cipher. 

The cipher is therefore a concatenation of RSA.Encrypt(AES.Key, AES.IV) and AES.Encrypt(data).

## For encryption the following steps happen:
1. Encrypt the AES key and IV using RSA encryption (see Tips for fast encryption).
2. Encrypt the data payload using AES encryption.
3. Concatenate the encrypted output of step 1 and 2 and that is the cipher.

## For decryption the following steps happen:
1. Decrypt the AES key and IV using RSA decryption (see Tips for fast decryption).
2. Decrypt the data payload using AES decryption and the key and IV decrypted from step 1.

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
Use a single instance of FastRsa. 

How this works is that it will encrypt the AES key and IV once, cache it and reuse it throughout the livetime of the FastRsa object. If you want a bit more security then dispose of the instance every X number of encryptions and create a new instance.

## Tips for fast decryption
For fast decryption there are two options:
1. Enable caching (recommended) 
2. Use the fast path

### Enable caching (recommended)
The FastRsa implementation uses a MemoryCache underneath that it uses to store AES Key and IV cipher along with the decrypted AES Key and IV. This eliminates subsequent RSA decryption to get the AES Key and IV and speeds up decryption significantly. RSA decryption is very slow therefore by eliminating it you speed up the decryption path.

When enabling the cache you can also specify CacheItemOptions which allows you to specify the following:
* Cache expiry type
	* Absolute expiry - Uses a fixed time to expire the cache whether it was accessed or not.
	* Sliding window - Uses the expiry time to expire the cache if the item wasn't accessed whithin that time.
* Cache expiry time

### Fast path
What fast path means is that if the cached encrypted AES key and IV matches that of the encrypted message then the FastRsa algorithm infers that it was encrypted using the current AES instance and thus won't decrypt the key cipher but will use the current AES instance instead. This is the fastest decryption but it isn't very flexible as you need to use the same EncryptedKeyAndIV over and over. 

Follow these steps to setup the fast path decryption:
1. Create a RSA public and private key pair and save the public key in your config.
3. Create an instance of FastRsa.
4. Print out or debug your program to get the EncryptedKeyAndIV property value from the FastRsa instance.
5. Copy the value of EncryptedKeyAndIV to your config.
6. Construct an instance of FastRsa and pass in the EncryptedKeyAndIV eg. new FastRsa(privateKey, EncryptedKeyAndIV);

By storing and supplying the EncryptedKeyAndIV to the FastRsa instance enables it to decrypt the key cipher and get the AES key and IV. When a message needs to be decrypted it will check if the key cipher is the same as the cipher cached EncryptedKeyAndIV property and if it is then it does not need to decrypt it but can use AES Key and IV it decrypted ducring instantiation. So the fast path in essence is the elimination of the RSA decryption of the AES key and IV which is expensive.

Please note that this is only recommended if you require speed above anything else. You can also combine this with caching.

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
|                              Method |       Mean |     Error |    StdDev |  Gen 0 | Gen 1 | Gen 2 | Allocated |
|------------------------------------ |-----------:|----------:|----------:|-------:|------:|------:|----------:|
|                  RsaEncrypt_1024Bit |  14.560 μs | 0.1048 μs | 0.0980 μs | 0.1678 |     - |     - |     720 B |
|                  RsaEncrypt_2048Bit |  33.266 μs | 0.2337 μs | 0.2072 μs | 0.2441 |     - |     - |   1,192 B |
|                   AesEncrypt_256Bit |   1.917 μs | 0.0379 μs | 0.0519 μs | 1.5564 |     - |     - |   6,512 B |
|              FastRsaEncrypt_1024Bit |   2.049 μs | 0.0409 μs | 0.0503 μs | 1.6747 |     - |     - |   7,008 B |
|              FastRsaEncrypt_2048Bit |   2.096 μs | 0.0415 μs | 0.0494 μs | 1.7548 |     - |     - |   7,352 B |
|                  RsaDecrypt_1024Bit | 118.308 μs | 1.1432 μs | 0.9546 μs | 0.1221 |     - |     - |     616 B |
|                  RsaDecrypt_2048Bit | 613.528 μs | 7.7043 μs | 7.2066 μs |      - |     - |     - |     872 B |
|                   AesDecrypt_256Bit |   2.203 μs | 0.0171 μs | 0.0134 μs | 1.0719 |     - |     - |   4,496 B |
|              FastRsaDecrypt_1024Bit |   2.722 μs | 0.0496 μs | 0.0571 μs | 1.2131 |     - |     - |   5,088 B |
|              FastRsaDecrypt_2048Bit |   2.927 μs | 0.0512 μs | 0.0479 μs | 1.2970 |     - |     - |   5,432 B |
| FastRsaDecrypt_1024Bit_CacheEnabled |   3.844 μs | 0.0643 μs | 0.0631 μs | 1.3390 |     - |     - |   5,616 B |
| FastRsaDecrypt_2048Bit_CacheEnabled |   4.215 μs | 0.0612 μs | 0.0542 μs | 1.4191 |     - |     - |   5,960 B |

FastRsa is extremely fast with encryption that rivals AES. 
By leveraging the caching or fast path during decryption, FastRsa is comparable to AES.

# FastRsa Use-cases
Here are a few use-cases of the FastRsa algorithm.

## Securely logging of PII data
In this case you need to log PII data for possible troubleshooting but due to acts such as GDPR it can't be plaintext and access to it needs to be controlled. What better way than to encrypt it using FastRsa and a public key which is known by the system and then adding the private key to a key vault with limited access.

## Sending PII data over an unsecured stream or queue
In this use case one system communicates with another system asynchronously over a public or unsecured stream or queue. Because you do not know who might be subscribed to the stream or queue it is advised that the message containing PII data be encrypted in order to protect against the PII leaking to unintended systems or actors. 

## Encrypting data for different recipients
If you have a system that needs to create sensitive messages that only the recipient is supposed to be able to read. This can be eitehr a person or another system, then your system would use the public key of the intended recipient and encrypt it. The recipient then know that the message is safe even if it was accidently sent to someone or something else or if there was a man-in-the-middle attack on your network.

## Encrypting and storing data on a possible unsafe or unsecured storage 
Sometimes you need to work with some shared infrastructure which a lot of people and systems have access to. A malicious actor either internal or external might be able to read sensitive data if a symmetric key is used. If the actor has access to the system that created the message, he/she would be able to decrypt the data. Therefore using FastRsa with a public key would protect your data because the malicious actor would need to their hands on the private key. 
