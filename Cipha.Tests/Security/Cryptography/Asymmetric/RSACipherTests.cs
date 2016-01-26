using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Asymmetric;
using Cipha.Security.Cryptography.Symmetric;
using System.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class RSACipherTests
    {
        [TestMethod]
        public void RSACipher_EncryptDecrypt_Pass()
        {
            string plainString = "Encrypt me via RSA";
            string encryptedString;
            string decryptedString;

            using(var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }

        [TestMethod]
        public void PassRSAParameter_ExportParameterWithPrivateKey_Pass()
        {
            string plainString = "Encrypt me via RSA";
            string plainkey = "";
            string encryptedString;
            string decryptedString;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                plainkey = cipher.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(plainkey))
            {
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }

        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void PassRSAParameter_ExportParameterWithoutPrivateKey_DecryptionWithPublicKeyFails()
        {
            string plainString = "Encrypt me via RSA";
            string plainkey = "";
            string encryptedString;
            string decryptedString;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                plainkey = cipher.ToXmlString(false);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(plainkey))
            {
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }

        [TestMethod]
        public void PassRSAParameter_ExportEncryptedParameterWithPrivateKey_Pass()
        {
            string plainString = "Encrypt me via RSA";
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };
            string passwd = "SafeP4ssw0rd;,,:;DWAe";
            string encryptedKey = "";
            string encryptedString;
            string decryptedString;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(new RSACryptoServiceProvider(2048)))
            {
                encryptedString = cipher.EncryptToString(plainString);
                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(true, passwd, salt);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(encryptedKey, passwd, salt))
            {
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }

        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void PassRSAParameter_ExportEncryptedParameterWithoutPrivateKey_DecryptionWithPublicKeyFails()
        {
            string plainString = "Encrypt me via RSA";
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };
            string passwd = "SafeP4ssw0rd;,,:;DWAe";
            string encryptedKey = "";
            string encryptedString;
            string decryptedString;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(false, passwd, salt);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(encryptedKey, passwd, salt))
            {
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }
        [TestMethod]
        public void RSAParameterEncryption_ExportEncryptedParameterWithPrivateKey_Pass()
        {
            string plainKey;
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };
            string passwd = "SafeP4ssw0rd;,,:;DWAe";
            string encryptedKey = "";

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                string plnKey = cipher.ToXmlString(true);
                using(var symCip = new SymmetricCipher<AesManaged>(passwd, salt))
                {
                    string encKey = symCip.EncryptToString(plnKey);
                    string decKey = symCip.DecryptToString(encKey);
                }


                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(true, passwd, salt);
                cipher.FromEncryptedXmlString<AesManaged>(encryptedKey, passwd, salt);
                plainKey = cipher.ToXmlString(true);
            }

            //Assert.AreEqual(plainKey, decryptedString);
        }

        [TestMethod]
        public void ChangeRSAKeySize_CreateInstance_Pass()
        {
            int wantedKeySize = 4096;
            int current = 0;
            using(var cipher = new RSACipher<RSACryptoServiceProvider>(wantedKeySize))
            {
                current = cipher.KeySize;
            }
            Assert.AreEqual(wantedKeySize, current);
        }
    }
}
