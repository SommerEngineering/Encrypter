using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Encrypter;
using NUnit.Framework;

namespace Encrypter_Tests
{
    public sealed class EncrypterTests
    {
        [Test]
        public async Task TestSimpleEnAndDecryption()
        {
            var message = "This is a test with umlauts äüö.";
            var password = "test password";

            var encryptedData = await CryptoProcessor.EncryptString(message, password);
            Assert.That(encryptedData.Length, Is.AtLeast(message.Length)); // Note: Encrypted data contains salt as well!

            var decryptedMessage = await CryptoProcessor.DecryptString(encryptedData, password);
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }
    }
}
