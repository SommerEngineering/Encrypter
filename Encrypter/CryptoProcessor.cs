using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    public static class CryptoProcessor
    {
        /// <summary>
        /// The number of iterations for the year 2020.
        /// </summary>
        public const int ITERATIONS_YEAR_2020 = 6_000_000;

        /// <summary>
        /// Encrypts a string by means of AES. The result gets base64 encoded.
        /// Due to the necessary millions of SHA512 iterations, the methods runs at least several seconds in the year 2020 (approx. 5-7s).
        /// This method suits for small data such as telegrams, JSON data, text notes, passwords, etc. For larger
        /// data, might use the stream overload. Rule of thumb: If the data could be stored three times in
        /// the present memory, this method could be used.
        /// </summary>
        /// <param name="data">The UTF8 encoded string to encrypt.</param>
        /// <param name="password">The password. Must consists of 6 chars or more.</param>
        /// <param name="iterations">The number of iterations to derive the key. Should not be adjusted. The default is secure for the current time.</param>
        /// <returns>The base64 encoded and encrypted string. The string is ASCII encoding.</returns>
        public static async Task<string> EncryptString(string data, string password, int iterations = ITERATIONS_YEAR_2020)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
                throw new CryptographicException("The password was empty or shorter than 6 characters.");

            if(data == null)
                throw new CryptographicException("The data cannot be null.");

            // Generate new random salt:
            var saltBytes = Guid.NewGuid().ToByteArray();

            // Derive key and iv vector:
            var key = new byte[32];
            var iv = new byte[16];

            // The following operations take several seconds. Thus, using a task:
            await Task.Run(() =>
            {
                using var keyVectorObj = new Rfc2898DeriveBytes(password, saltBytes, iterations, HashAlgorithmName.SHA512);
                key = keyVectorObj.GetBytes(32); // the max valid key length = 256 bit = 32 bytes
                iv = keyVectorObj.GetBytes(16); // the only valid block size = 128 bit = 16 bytes
            });

            // Create AES encryption:
            using var aes = Aes.Create();
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using var encryption = aes.CreateEncryptor();

            // Copy the given string data into a memory stream
            await using var plainDataStream = new MemoryStream(Encoding.UTF8.GetBytes(data));

            // A memory stream for the final, encrypted data:
            await using var encryptedAndEncodedData = new MemoryStream();
            
            // A base64 stream for the encoding:
            await using var base64Stream = new CryptoStream(encryptedAndEncodedData, new ToBase64Transform(), CryptoStreamMode.Write);

            // Write the salt into the base64 stream:
            await base64Stream.WriteAsync(saltBytes);

            // Create the encryption stream:
            await using var cryptoStream = new CryptoStream(base64Stream, encryption, CryptoStreamMode.Write);

            // Write the payload into the encryption stream:
            await plainDataStream.CopyToAsync(cryptoStream);
            
            // Flush the final block. Please note, that it is not enough to call the regular flush method!
            cryptoStream.FlushFinalBlock();
            
            // Clears all sensitive information:
            aes.Clear();
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            password = string.Empty;

            // Convert the base64 encoded data back into a string. Uses GetBuffer due to the advantage, that
            // it does not create another copy of the data. ToArray would create another copy of the data!
            return Encoding.ASCII.GetString(encryptedAndEncodedData.GetBuffer()[..(int)encryptedAndEncodedData.Length]);
        }

        /// <summary>
        /// Decrypts an base64 encoded and encrypted string. Due to the necessary millions of SHA512 iterations,
        /// the methods runs at least several seconds in the year 2020 (approx. 5-7s).
        /// This method suits for small data such as telegrams, JSON data, text notes, passwords, etc. For larger
        /// data, might use the stream overload. Rule of thumb: If the data could be stored three times in
        /// the present memory, this method could be used.
        /// </summary>
        /// <param name="base64EncodedAndEncryptedData">The base64 encoded and AES encrypted string. This string must be ASCII encoded.</param>
        /// <param name="password">The password. Must consists of 6 chars or more.</param>
        /// <param name="iterations">The number of iterations to derive the key. Should not be adjusted. The default is secure for the current time.</param>
        /// <returns>The decrypted UTF8 encoded string.</returns>
        public static async Task<string> DecryptString(string base64EncodedAndEncryptedData, string password, int iterations = ITERATIONS_YEAR_2020)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
                throw new CryptographicException("The password was empty or shorter than 6 characters.");

            if (base64EncodedAndEncryptedData == null)
                throw new CryptographicException("The data cannot be null.");

            // Build a memory stream to access the given base64 encoded data:
            await using var encodedEncryptedStream = new MemoryStream(Encoding.ASCII.GetBytes(base64EncodedAndEncryptedData));

            // Wrap around the base64 decoder stream:
            await using var base64Stream = new CryptoStream(encodedEncryptedStream, new FromBase64Transform(), CryptoStreamMode.Read);

            // A buffer for the salt's bytes:
            var saltBytes = new byte[16]; // 16 bytes = Guid

            // Read the salt's bytes out of the stream:
            await base64Stream.ReadAsync(saltBytes, 0, saltBytes.Length);

            // Derive key and iv vector:
            var key = new byte[32];
            var iv = new byte[16];

            // The following operations take several seconds. Thus, using a task:
            await Task.Run(() =>
            {
                using var keyVectorObj = new Rfc2898DeriveBytes(password, saltBytes, iterations, HashAlgorithmName.SHA512);
                key = keyVectorObj.GetBytes(32); // the max valid key length = 256 bit = 32 bytes
                iv = keyVectorObj.GetBytes(16); // the only valid block size = 128 bit = 16 bytes
            });

            // Create AES decryption:
            using var aes = Aes.Create();
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using var decryption = aes.CreateDecryptor();

            // A memory stream for the final, decrypted data:
            await using var decryptedData = new MemoryStream();

            // The crypto stream:
            await using var cryptoStream = new CryptoStream(base64Stream, decryption, CryptoStreamMode.Read);
            
            // Reads all remaining data trough the decrypt stream. Note, that this operation
            // starts at the current position, i.e. after the salt bytes:
            await cryptoStream.CopyToAsync(decryptedData);

            // Clears all sensitive information:
            aes.Clear();
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            password = string.Empty;

            // Convert the decrypted data back into a string. Uses GetBuffer due to the advantage, that
            // it does not create another copy of the data. ToArray would create another copy of the data!
            return Encoding.UTF8.GetString(decryptedData.GetBuffer()[..(int)decryptedData.Length]);
        }

        /// <summary>
        /// Upgrades the encryption regarding the used iterations for the key.
        /// </summary>
        /// <param name="encryptedDataBeforeUpgrade">The encrypted data with the previous settings.</param>
        /// <param name="password">The password.</param>
        /// <param name="previousIterations">The previous number of iterations.</param>
        /// <param name="upgradedIterations">The upgraded number of iterations.</param>
        /// <returns>The re-encrypted data.</returns>
        public static async Task<string> UpgradeIterations(string encryptedDataBeforeUpgrade, string password, int previousIterations, int upgradedIterations)
        {
            // Decrypt the data with the previous settings:
            var decryptedData = await CryptoProcessor.DecryptString(encryptedDataBeforeUpgrade, password, previousIterations);

            // Encrypt the data with the new settings:
            return await CryptoProcessor.EncryptString(decryptedData, password, upgradedIterations);
        }
    }
}
