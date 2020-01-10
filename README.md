# About this library
This library implements the Advanced Encryption Standard "AES" (cf. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) for strings and arbitrary streams (databases, network, files, etc.) The string implementation uses a base64 encoding so that the encrypted data can still be treated as text data. The stream implementation can be used for very large amounts of data, even if that data does not fit in memory.

All interfaces use the C# `async` keyword, so they can be used in user interface apps without making the user interface unusable while operations are running. By default, this library uses 6 million iterations to derive a key, so that about 5-7 seconds of computing time are needed per encryption and decryption process in 2020. As long as a strong password is used, the data is securely encrypted. A brute-force attack is therefore not successful in the short term. The number of iterations can be increased e.g. annually, if the generally available computing capacity is also increased e.g. by newer CPUs.

Implemented features:
- Encrypting strings and arbitrary streams
- Decrypting strings and arbitrary streams
- Upgrading the used iterations for deriving the key
- Changing the password

# .NET Core 3.1 LTS+ only
This library was implemented especially for .NET Core 3.1 and newer. It is therefore not available for .NET Standard 2.x or the outdated .NET Framework. This design decision was made based on the following background: (a) The .NET Framework will not be further developed (cf. https://devblogs.microsoft.com/dotnet/net-core-is-the-future-of-net/); (b) as of .NET 5.0, the .NET Standard is no longer expected to be required because Mono and the .NET Core will be merged together into the new .NET 5 (cf. https://devblogs.microsoft.com/dotnet/introducing-net-5/).

# Test cases
This library contains test cases for the most important functions to ensure functionality.

# Citation
The library can also be cited in scientific works, for example as follows:

*Sommer, Thorsten (2020): Encrypter. Github: https://github.com/SommerEngineering/Encrypter, DOI: [doi.org/10.5281/zenodo.3601357](https://doi.org/10.5281/zenodo.3601357)*

# License
This library uses the BSD 3-clause license.