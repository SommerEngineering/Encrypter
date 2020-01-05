﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        public async Task TestAlteredPassword()
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

        [Test]
        public async Task TestChangedPasswordBehaviour()
        {
            var message = "This is a test with umlauts äüö.";
            var previousPassword = "test password";
            var newPassword = "test password!!!";
            var iterations = 1_000;

            var previousEncryptedData = await CryptoProcessor.EncryptString(message, previousPassword, iterations);
            var reEncryptedData = await CryptoProcessor.ChangePassword(previousEncryptedData, previousPassword, newPassword, iterations);
            Assert.That(previousEncryptedData, Is.Not.EqualTo(reEncryptedData));

            var decryptedMessage = await CryptoProcessor.DecryptString(reEncryptedData, newPassword, iterations);
            Assert.That(decryptedMessage, Is.EqualTo(message));

            try
            {
                var decryptedMessage2 = await CryptoProcessor.DecryptString(reEncryptedData, previousPassword, iterations);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }

            try
            {
                var decryptedMessage2 = await CryptoProcessor.DecryptString(previousEncryptedData, newPassword, iterations);
                Assert.Fail("Should not be reached!");
            }
            catch (CryptographicException e)
            {
                Assert.That(true);
            }
        }

        [Test]
        public async Task TestSimpleStream()
        {
            var message = "This is a test with umlauts äüö.";
            var tempSourceFile = Path.GetTempFileName();
            var tempDestFile = Path.GetTempFileName();
            var tempFinalFile = Path.GetTempFileName();
            var password = "test password";

            try
            {
                await File.WriteAllTextAsync(tempSourceFile, message);
                await CryptoProcessor.EncryptStream(File.OpenRead(tempSourceFile), File.OpenWrite(tempDestFile), password);
                await CryptoProcessor.DecryptStream(File.OpenRead(tempDestFile), File.OpenWrite(tempFinalFile), password);

                Assert.That(File.Exists(tempDestFile), Is.True);
                Assert.That(File.Exists(tempFinalFile), Is.True);
                Assert.That(File.ReadAllText(tempFinalFile), Is.EqualTo(message));
            }
            finally
            {
                try
                {
                    File.Delete(tempSourceFile);
                }
                catch
                {
                }

                try
                {
                    File.Delete(tempDestFile);
                }
                catch
                {
                }

                try
                {
                    File.Delete(tempFinalFile);
                }
                catch
                {
                }
            }
        }

        [Test]
        public async Task Test32GBStream()
        {
            var tempSourceFile = Path.GetTempFileName();
            var tempDestFile = Path.GetTempFileName();
            var tempFinalFile = Path.GetTempFileName();
            var password = "test password";

            try
            {
                // Write 32 GB random data:
                await using (var stream = File.OpenWrite(tempSourceFile))
                {
                    var rnd = new Random();
                    var buffer = new byte[512_000];
                    var iterations = 32_000_000_000 / buffer.Length;
                    for(var n=0; n < iterations; n++)
                    {
                        rnd.NextBytes(buffer);
                        await stream.WriteAsync(buffer);
                    }
                }

                var fileInfoSource = new FileInfo(tempSourceFile);
                Assert.That(fileInfoSource.Length, Is.EqualTo(32_000_000_000));

                await CryptoProcessor.EncryptStream(File.OpenRead(tempSourceFile), File.OpenWrite(tempDestFile), password);
                await CryptoProcessor.DecryptStream(File.OpenRead(tempDestFile), File.OpenWrite(tempFinalFile), password);

                Assert.That(File.Exists(tempDestFile), Is.True);
                Assert.That(File.Exists(tempFinalFile), Is.True);

                var fileInfoEncrypted = new FileInfo(tempDestFile);
                var fileInfoFinal = new FileInfo(tempFinalFile);

                Assert.That(fileInfoEncrypted.Length, Is.GreaterThan(32_000_000_000));
                Assert.That(fileInfoFinal.Length, Is.EqualTo(fileInfoSource.Length));

                var identical = true;
                await using (var sourceStream = File.OpenRead(tempSourceFile))
                {
                    await using var finalStream = File.OpenRead(tempFinalFile);

                    var bufferSource = new byte[512_000];
                    var bufferFinal = new byte[512_000];
                    var iterations = 32_000_000_000 / bufferSource.Length;
                    for (var n = 0; n < iterations; n++)
                    {
                        await sourceStream.ReadAsync(bufferSource, 0, bufferSource.Length);
                        await finalStream.ReadAsync(bufferFinal, 0, bufferFinal.Length);

                        if (!bufferSource.SequenceEqual(bufferFinal))
                        {
                            identical = false;
                            break;
                        }
                    }
                }

                Assert.That(identical, Is.True);
            }
            finally
            {
                try
                {
                    File.Delete(tempSourceFile);
                }
                catch
                {
                }

                try
                {
                    File.Delete(tempDestFile);
                }
                catch
                {
                }

                try
                {
                    File.Delete(tempFinalFile);
                }
                catch
                {
                }
            }
        }
    }
}
