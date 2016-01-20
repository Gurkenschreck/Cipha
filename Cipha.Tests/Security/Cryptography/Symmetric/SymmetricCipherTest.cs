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
        public void AesBasicCipher1_SameInstance_ComparesOutput()
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
        }
    }
}
