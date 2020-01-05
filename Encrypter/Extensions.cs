using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    public static class Extensions
    {
        /// <summary>
        /// Encrypts this string by means of AES. The result gets base64 encoded.
        /// Due to the necessary millions of SHA512 iterations, the methods runs at least several seconds in the year 2020 (approx. 5-7s).
        /// This method suits for small data such as telegrams, JSON data, text notes, passwords, etc. For larger
        /// data, might use the stream overload. Rule of thumb: If the data could be stored three times in
        /// the present memory, this method could be used.
        /// </summary>
        /// <param name="data">This UTF8 encoded string to encrypt.</param>
        /// <param name="password">The password. Must consists of 6 chars or more.</param>
        /// <returns>The base64 encoded and encrypted string. The string is ASCII encoding.</returns>
        public static async Task<string> Encrypt(this string data, string password)
        {
            return await CryptoProcessor.EncryptString(data, password);
        }

        /// <summary>
        /// Decrypts an base64 encoded and encrypted string. Due to the necessary millions of SHA512 iterations,
        /// the methods runs at least several seconds in the year 2020 (approx. 5-7s).
        /// This method suits for small data such as telegrams, JSON data, text notes, passwords, etc. For larger
        /// data, might use the stream overload. Rule of thumb: If the data could be stored three times in
        /// the present memory, this method could be used.
        /// </summary>
        /// <param name="data">The base64 encoded and AES encrypted string. This string must be ASCII encoded.</param>
        /// <param name="password">The password. Must consists of 6 chars or more.</param>
        /// <returns>The decrypted UTF8 encoded string.</returns>
        public static async Task<string> Decrypt(this string data, string password)
        {
            return await CryptoProcessor.DecryptString(data, password);
        }
    }
}
