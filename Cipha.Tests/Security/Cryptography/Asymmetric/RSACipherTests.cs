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
            byte[] IV;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(new RSACryptoServiceProvider(2048)))
            {
                encryptedString = cipher.EncryptToString(plainString);
                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(true, passwd, salt, out IV);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(encryptedKey, passwd, salt, IV))
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
            byte[] IV = null;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                encryptedString = cipher.EncryptToString(plainString);
                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(false, passwd, salt, out IV);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(encryptedKey, passwd, salt, IV))
            {
                decryptedString = cipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }
        [TestMethod]
        public void RSAParameterEncryption_ExportEncryptedParameterWithPrivateKey_Pass()
        {
            string plainKey = "soonAssigned";
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };
            string passwd = "SafeP4ssw0rd;,,:;DWAe";
            string encryptedKey = "";
            string decryptedKey = "laterAssigned";
            byte[] IV;

            using (var cipher = new RSACipher<RSACryptoServiceProvider>())
            {
                plainKey = cipher.ToXmlString(true);
                encryptedKey = cipher.ToEncryptedXmlString<AesManaged>(true, passwd, salt, out IV);
                cipher.FromEncryptedXmlString<AesManaged>(encryptedKey, passwd, salt, IV);
                decryptedKey = cipher.ToXmlString(true);
            }

            Assert.AreEqual(plainKey, decryptedKey);
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

        [TestMethod]
        public void SignData_CompareSignaturesOfRSACSPAndRSACipher_Pass()
        {
            int wantedKeySize = 4096;
            Random rdm = new Random();
            byte[] message = new byte[256];
            byte[] signedMessage;
            byte[] signedMessageNative;
            string nativeXmlString;
            rdm.NextBytes(message);

            using(var rsacsp = new RSACryptoServiceProvider(wantedKeySize))
            {
                signedMessageNative = rsacsp.SignData(message, new SHA512Managed());
                nativeXmlString = rsacsp.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(nativeXmlString))
            {
                signedMessage = cipher.SignData<SHA512Managed>(message);
            }

            CollectionAssert.AreEqual(signedMessage, signedMessageNative);
        }
        [TestMethod]
        public void SignHash_CompareSignaturesOfRSACSPAndRSACipher_Pass()
        {
            int wantedKeySize = 4096;
            Random rdm = new Random();
            byte[] message = new byte[256];
            byte[] signedMessage;
            byte[] signedMessageNative;
            string nativeXmlString;
            rdm.NextBytes(message);

            using (var rsacsp = new RSACryptoServiceProvider(wantedKeySize))
            {
                byte[] native = new SHA1Cng().ComputeHash(message);
                signedMessageNative = rsacsp.SignHash(native, "SHA1");
                nativeXmlString = rsacsp.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(nativeXmlString))
            {
                //byte[] hash = new SHA1Managed().ComputeHash(message);
                signedMessage = cipher.ComputeAndSignHash<SHA1Cng>(message);
            }

            CollectionAssert.AreEqual(signedMessage, signedMessageNative);
        }
        [TestMethod]
        public void VerifyData_VerifiesComputedSignature_Pass()
        {
            Random rdm = new Random();
            byte[] message = new byte[256];
            byte[] signedMessage;
            string nativeXmlString;
            bool isMessageNotTamperedWith = true;
            rdm.NextBytes(message);

            using (var rsacsp = new RSACipher<RSACryptoServiceProvider>())
            {
                signedMessage = rsacsp.SignData<SHA256Cng>(message);
                nativeXmlString = rsacsp.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(nativeXmlString))
            {
                isMessageNotTamperedWith = cipher.VerifyData<SHA256Cng>(message, signedMessage);
            }

            Assert.IsTrue(isMessageNotTamperedWith);
        }
        [TestMethod]
        public void ComputeAndSignHash_VerifiesComputedSignature_Pass()
        {
            Random rdm = new Random();
            byte[] message = new byte[256];
            byte[] signedMessage;
            string nativeXmlString;
            bool isMessageNotTamperedWith = true;
            rdm.NextBytes(message);

            using (var rsacsp = new RSACipher<RSACryptoServiceProvider>())
            {
                signedMessage = rsacsp.ComputeAndSignHash<SHA384Cng>(message);
                nativeXmlString = rsacsp.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(nativeXmlString))
            {
                isMessageNotTamperedWith = cipher.ComputeAndVerifyHash<SHA384Cng>(message, signedMessage);
            }

            Assert.IsTrue(isMessageNotTamperedWith);
        }

        [TestMethod]
        public void SignHash_VerifiesComputedSignature_Pass()
        {
            Random rdm = new Random();
            byte[] message = new byte[256];
            byte[] signedMessage;
            string nativeXmlString;
            bool isMessageNotTamperedWith = true;
            rdm.NextBytes(message);

            using (var rsacsp = new RSACipher<RSACryptoServiceProvider>())
            {
                byte[] firstHash = new SHA256Managed().ComputeHash(message);
                signedMessage = rsacsp.SignHash(firstHash);
                nativeXmlString = rsacsp.ToXmlString(true);
            }

            using (var cipher = new RSACipher<RSACryptoServiceProvider>(nativeXmlString))
            {
                byte[] n = new SHA256Managed().ComputeHash(message);
                isMessageNotTamperedWith = cipher.VerifyHash(n, signedMessage);
            }

            Assert.IsTrue(isMessageNotTamperedWith);
        }
    }
}
