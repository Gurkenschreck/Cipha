using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Symmetric;
using System.Security.Cryptography;
using System.Text;

namespace Cipha.Tests.Security.Cryptography.Symmetric
{
    [TestClass]
    public class SymmetricCipherTest
    {
        [TestMethod]
        public void ConstructorWithSaltLength_InstantiateNewObjectWithSaltLength_Pass()
        {
            int saltLength = 55;
            int actualLength;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd", saltLength))
            {
                actualLength = cipher.Salt.Length;
            }

            Assert.AreEqual(saltLength, actualLength);
        }
        [TestMethod]
        public void ConstructorWithRandomSalt_InstantiateNewObjectWithDefaultSaltLength_Pass()
        {
            int saltLength = 64;
            int actualLength;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd"))
            {
                actualLength = cipher.Salt.Length;
            }

            Assert.AreEqual(saltLength, actualLength);
        }
        [TestMethod]
        public void EncryptToString_AesEncryptToStringAndDecryptToString_Pass()
        {
            string plainText = "Encrypt me but don' forget me.";
            string encryptedText;
            string decryptedText;
            using(var cipher = new SymmetricCipher<AesManaged>("passwd", "mysalt1337"))
            {
                encryptedText = cipher.EncryptToString(plainText);
                decryptedText = cipher.DecryptToString(encryptedText);
            }

            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void AesBasicCipher1_SameInstance_ComparesOutput()
        {
            string plainText = "Encrypt me but don' forget me.";
            byte[] plaindata = Encoding.UTF8.GetBytes(plainText);
            string encryptedText;
            string decryptedText;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd", "mysalt1337"))
            {
                encryptedText = cipher.EncryptToString(plaindata);
                decryptedText = cipher.DecryptToString(encryptedText);
            }

            Assert.AreEqual(plainText, decryptedText);
        }
        [TestMethod]
        public void DecryptToString_EncryptAndDecryptToString_Pass()
        {
            string plainText = "Encrypt me but don' forget me.";
            byte[] plaindata = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedText;
            string decryptedText;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd", "mysalt1337"))
            {
                encryptedText = cipher.Encrypt(plaindata);
                decryptedText = cipher.DecryptToString(encryptedText);
            }

            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void AesBasicCipher2_SameInstance_ComparesOutput()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;
            string decryptStr;

            using(var cipher = new SymmetricCipher<AesManaged>("mypasswd", "mysalt1337"))
            {
                encryptArr = cipher.Encrypt(plainTextArr);
                decryptArr = cipher.Decrypt(encryptArr);
            }
            decryptStr = Encoding.UTF8.GetString(decryptArr);

            Assert.AreEqual(plainText, decryptStr);
        }

        [TestMethod]
        public void AesBasicCipher3_SameInstance_ComparesOutput()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;
            string decryptStr;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb"))
            {
                encryptArr = cipher.Encrypt(plainText);
                decryptArr = cipher.Decrypt(encryptArr);
            }
            decryptStr = Encoding.UTF8.GetString(decryptArr);

            Assert.AreEqual(plainText, decryptStr);
        }
        [TestMethod]
        public void AesBasicCipher4_SameInstance_ComparesOutput()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            string encryptStr;
            byte[] decryptArr;
            string decryptStr;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb"))
            {
                encryptStr = cipher.EncryptToString(plainText);
                decryptArr = cipher.Decrypt(encryptStr);
            }
            decryptStr = Encoding.UTF8.GetString(decryptArr);

            Assert.AreEqual(plainText, decryptStr);
        }
        
        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void AesBasicCipher_MultiInstance_WrongPasswdFail()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2;", "mysalt1337bb"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }
        }

        [TestCategory("SymmetricCipherTests")]
        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void AesBasicCipher_MultiInstance_WrongSaltFail()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }
        }

        [TestMethod]
        public void Constructor_ChangeKeySize_ExpectedKey()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            int keySize = 128;
            int newKeySize;
            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44", keysize: keySize))
            {
                newKeySize = cipher.Algorithm.KeySize;
            }

            Assert.AreEqual(keySize, newKeySize);
        }

        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void Constructor_ChangeKeySize_FailDueToInvalidKeySize()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            int keySize = 234;
            int newKeySize;
            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44", keysize: keySize))
            {
                newKeySize = cipher.Algorithm.KeySize;
            }

            Assert.AreEqual(keySize, newKeySize);
        }

        [TestMethod]
        public void BasicCipher_AesSimpleCryption_ShouldPass()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }
        [TestMethod]
        public void BasicCipher_RijndaelSimpleCryption_ShouldPass()
        {
            string plainText = "Encryption is pretty fun";
            string passwd = "mypasswd2";
            string salt = "mysalt1337bb44";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<RijndaelManaged>(passwd, salt))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<RijndaelManaged>(passwd, salt))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }
        [TestMethod]
        public void BasicCipher_DESSimpleCryption_ShouldPass()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<DESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<DESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }
        [TestMethod]
        public void BasicCipher_RC2SimpleCryption_ShouldPass()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<RC2CryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<RC2CryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }
        [TestMethod]
        public void BasicCipher_TrippleDESSimpleCryption_ShouldPass()
        {
            string plainText = "Encryption is pretty fun";
            byte[] plainTextArr = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptArr;
            byte[] decryptArr;

            using (var cipher = new SymmetricCipher<TripleDESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<TripleDESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }

    }
}
