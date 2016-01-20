using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Asymmetric;
using System.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class AsymmetricCipherTest
    {
        [TestMethod]
        public void RSACipher_EncryptDecrypt_Pass()
        {
            string plainString = "Encrypt me via RSA";
            string encryptedString;
            string decryptedString;

            using(var cipher = new AsymmetricCipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                decryptedString = cipher.DecryptToString(encryptedString);

            }

            Assert.AreEqual(plainString, decryptedString);
        }
        [TestMethod]
        public void PassRSAParameter_ExportParameter_Pass()
        {
            string plainString = "Encrypt me via RSA";
            string encryptedString;
            string decryptedString;

            using (var cipher = new AsymmetricCipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                decryptedString = cipher.DecryptToString(encryptedString);

            }

            Assert.AreEqual(plainString, decryptedString);
        }
    }
}
