using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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

        [Test]
        public async Task TestEmptyMessage()
        {
            var message = string.Empty;
            var password = "test password";

            var encryptedData = await CryptoProcessor.EncryptString(message, password);
            var decryptedMessage = await CryptoProcessor.DecryptString(encryptedData, password);
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }

        [Test]
        public async Task TestNoMessage()
        {
            string message = null;
            var password = "test password";

            try
            {
                var encryptedData = await CryptoProcessor.EncryptString(message, password);
                Assert.Fail("Should not be reached!");
            }
            catch(CryptographicException e)
            {
                Assert.That(true);
            }
        }

        [Test]
        public async Task TestTooShortPassword4Encryption()
        {
            var message = "This is a test with umlauts äüö.";
            var password = "test";

            try
            {
                var encryptedData = await CryptoProcessor.EncryptString(message, password);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }
        }

        [Test]
        public async Task TestTooShortPassword4Decryption()
        {
            var message = "This is a test with umlauts äüö.";
            var password = "test password";

            var encryptedData = await CryptoProcessor.EncryptString(message, password);
            
            try
            {
                var decryptedMessage = await CryptoProcessor.DecryptString(encryptedData, password[..4]);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }
        }

        [Test]
        public async Task TestSimpleEnAndDecryptionWithASCII()
        {
            var message = Encoding.ASCII.GetString(Encoding.Convert(Encoding.UTF8, Encoding.ASCII, Encoding.UTF8.GetBytes("This is a test without umlauts.")));
            var password = "test password";

            var encryptedData = await CryptoProcessor.EncryptString(message, password);
            var decryptedMessage = await CryptoProcessor.DecryptString(encryptedData, password);
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }

        [Test]
        public async Task TestChangedPassword()
        {
            var message = "This is a test with umlauts äüö.";
            var password1 = "password!";
            var password2 = "password.";

            var encryptedData = await CryptoProcessor.EncryptString(message, password1);

            try
            {
                var decryptedMessage = await CryptoProcessor.DecryptString(encryptedData, password2);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }
        }

        [Test]
        public async Task TestSimpleExtensionMethods()
        {
            var message = "This is a test with umlauts äüö.";
            var password = "test password";

            var encryptedData = await message.Encrypt(password);
            var decryptedMessage = await encryptedData.Decrypt(password);
            Assert.That(decryptedMessage, Is.EqualTo(message));
        }

        [Test]
        public async Task TestUpgradedIterationsBehaviour()
        {
            var message = "This is a test with umlauts äüö.";
            var password = "test password";
            var previousIterations = 1_000;
            var upgradedIterations = 1_000_000;

            var previousEncryptedData = await CryptoProcessor.EncryptString(message, password, previousIterations);
            var reEncryptedData = await CryptoProcessor.UpgradeIterations(previousEncryptedData, password, previousIterations, upgradedIterations);
            Assert.That(previousEncryptedData, Is.Not.EqualTo(reEncryptedData));
            
            var decryptedMessage = await CryptoProcessor.DecryptString(reEncryptedData, password, upgradedIterations);
            Assert.That(decryptedMessage, Is.EqualTo(message));

            try
            {
                var decryptedMessage2 = await CryptoProcessor.DecryptString(reEncryptedData, password, previousIterations);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }

            try
            {
                var decryptedMessage2 = await CryptoProcessor.DecryptString(previousEncryptedData, password, upgradedIterations);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }
        }
    }
}
