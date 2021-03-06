﻿using System;
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
        public static async Task<string> Encrypt(string data, string password, int iterations = ITERATIONS_YEAR_2020)
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
            aes.Mode = CipherMode.CBC;

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
        /// Encrypts a given input stream and writes the encrypted data to the provided output stream. A buffer stream
        /// gets used in front of the output stream. This method expects, that both streams are read-to-use e.g. the
        /// input stream is at the desired position and the output stream is writable, etc. This method disposes the
        /// internal crypto streams. Thus, the input and output streams might get disposed as well. Please note, that
        /// this method writes binary data without e.g. base64 encoding.
        ///
        /// When the task finished, the entire encryption of the input stream is done.
        /// </summary>
        /// <param name="inputStream">The desired input stream. The encryption starts at the current position.</param>
        /// <param name="outputStream">The desired output stream. The encrypted data gets written to the current position.</param>
        /// <param name="password">The encryption password.</param>
        /// <param name="iterations">The desired number of iterations to create the key. Should not be adjusted. The default is secure for the current time.</param>
        public static async Task Encrypt(Stream inputStream, Stream outputStream, string password, int iterations = ITERATIONS_YEAR_2020)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
                throw new CryptographicException("The password was empty or shorter than 6 characters.");

            if (inputStream == null)
                throw new CryptographicException("The input stream cannot be null.");

            if (outputStream == null)
                throw new CryptographicException("The output stream cannot be null.");

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
            aes.Mode = CipherMode.CBC;

            using var encryption = aes.CreateEncryptor();

            // A buffer stream for the output:
            await using var bufferOutputStream = new BufferedStream(outputStream, 65_536);

            // Write the salt into the base64 stream:
            await bufferOutputStream.WriteAsync(saltBytes);

            // Create the encryption stream:
            await using var cryptoStream = new CryptoStream(bufferOutputStream, encryption, CryptoStreamMode.Write);

            // Write the payload into the encryption stream:
            await inputStream.CopyToAsync(cryptoStream);

            // Flush the final block. Please note, that it is not enough to call the regular flush method!
            cryptoStream.FlushFinalBlock();

            // Clears all sensitive information:
            aes.Clear();
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            password = string.Empty;

            // Waits for the buffer stream to finish:
            await bufferOutputStream.FlushAsync();
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
        public static async Task<string> Decrypt(string base64EncodedAndEncryptedData, string password, int iterations = ITERATIONS_YEAR_2020)
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
        /// Decrypts a given input stream and writes the decrypted data to the provided output stream. A buffer stream
        /// gets used in front of the output stream. This method expects, that both streams are read-to-use e.g. the
        /// input stream is at the desired position and the output stream is writable, etc. This method disposes the
        /// internal crypto streams. Thus, the input and output streams might get disposed as well. Please note, that
        /// this method writes binary data without e.g. base64 encoding.
        ///
        /// When the task finished, the entire decryption of the input stream is done.
        /// </summary>
        /// <param name="inputStream">The desired input stream. The decryption starts at the current position.</param>
        /// <param name="outputStream">The desired output stream. The decrypted data gets written to the current position.</param>
        /// <param name="password">The encryption password.</param>
        /// <param name="iterations">The desired number of iterations to create the key. Should not be adjusted. The default is secure for the current time.</param>
        public static async Task Decrypt(Stream inputStream, Stream outputStream, string password, int iterations = ITERATIONS_YEAR_2020)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
                throw new CryptographicException("The password was empty or shorter than 6 characters.");

            if (inputStream == null)
                throw new CryptographicException("The input stream cannot be null.");

            if (outputStream == null)
                throw new CryptographicException("The output stream cannot be null.");

            // A buffer for the salt's bytes:
            var saltBytes = new byte[16]; // 16 bytes = Guid

            // Read the salt's bytes out of the stream:
            await inputStream.ReadAsync(saltBytes, 0, saltBytes.Length);

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

            // The crypto stream:
            await using var cryptoStream = new CryptoStream(inputStream, decryption, CryptoStreamMode.Read);

            // Create a buffer stream in front of the output stream:
            await using var bufferOutputStream = new BufferedStream(outputStream);

            // Reads all remaining data trough the decrypt stream. Note, that this operation
            // starts at the current position, i.e. after the salt bytes:
            await cryptoStream.CopyToAsync(bufferOutputStream);

            // Clears all sensitive information:
            aes.Clear();
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            password = string.Empty;

            // Waits for the buffer stream to finish:
            await bufferOutputStream.FlushAsync();
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
            var decryptedData = await CryptoProcessor.Decrypt(encryptedDataBeforeUpgrade, password, previousIterations);

            // Encrypt the data with the new settings:
            return await CryptoProcessor.Encrypt(decryptedData, password, upgradedIterations);
        }

        /// <summary>
        /// Upgrades the encryption regarding the used iterations for the key. In order to re-encrypt the stream, a temporary file
        /// gets used. When the returned task is finished, the re-encryption is done as well.
        /// </summary>
        /// <param name="inputStreamBeforeUpgrade">The encrypted data with the previous settings.</param>
        /// <param name="outputStreamUpgraded">The re-encrypted data.</param>
        /// <param name="password">The password.</param>
        /// <param name="previousIterations">The previous number of iterations.</param>
        /// <param name="upgradedIterations">The upgraded number of iterations.</param>
        public static async Task UpgradeIterations(Stream inputStreamBeforeUpgrade, Stream outputStreamUpgraded, string password, int previousIterations, int upgradedIterations)
        {
            var tempFileCache = Path.GetTempFileName();

            try
            {
                await using (var tempCacheStream = File.OpenWrite(tempFileCache))
                {
                    // Decrypt the data with the previous settings:
                    await Decrypt(inputStreamBeforeUpgrade, tempCacheStream, password, previousIterations);
                }

                await using (var tempCacheStream = File.OpenRead(tempFileCache))
                {
                    // Encrypt the data with the new settings:
                    await Encrypt(tempCacheStream, outputStreamUpgraded, password, upgradedIterations);
                }
            }
            finally
            {
                try
                {
                    File.Delete(tempFileCache);
                }
                catch
                {
                }
            }
        }

        /// <summary>
        /// Changes the password of the encryption.
        /// </summary>
        /// <param name="encryptedDataBeforeChange">With the previous password encrypted data.</param>
        /// <param name="previousPassword">The previous password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="iterations">The used iterations.</param>
        /// <returns>The re-encrypted data.</returns>
        public static async Task<string> ChangePassword(string encryptedDataBeforeChange, string previousPassword, string newPassword, int iterations = ITERATIONS_YEAR_2020)
        {
            // Decrypt the data with the previous settings:
            var decryptedData = await CryptoProcessor.Decrypt(encryptedDataBeforeChange, previousPassword, iterations);

            // Encrypt the data with the new settings:
            return await CryptoProcessor.Encrypt(decryptedData, newPassword, iterations);
        }

        /// <summary>
        /// Changes the password of the encryption. In order to re-encrypt the stream, a temporary file
        /// gets used. When the returned task is finished, the re-encryption is done as well.
        /// </summary>
        /// <param name="encryptedInput">With the previous password encrypted data.</param>
        /// <param name="reEncryptedOutput">The re-encrypted data.</param>
        /// <param name="previousPassword">The previous password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="iterations">The used iterations.</param>
        public static async Task ChangePassword(Stream encryptedInput, Stream reEncryptedOutput, string previousPassword, string newPassword, int iterations = ITERATIONS_YEAR_2020)
        {
            var tempFileCache = Path.GetTempFileName();

            try
            {
                await using (var tempCacheStream = File.OpenWrite(tempFileCache))
                {
                    // Decrypt the data with the previous settings:
                    await Decrypt(encryptedInput, tempCacheStream, previousPassword, iterations);
                }

                await using (var tempCacheStream = File.OpenRead(tempFileCache))
                {
                    // Encrypt the data with the new settings:
                    await Encrypt(tempCacheStream, reEncryptedOutput, newPassword, iterations);
                }
            }
            finally
            {
                try
                {
                    File.Delete(tempFileCache);
                }
                catch
                {
                }
            }
        }
    }
}
