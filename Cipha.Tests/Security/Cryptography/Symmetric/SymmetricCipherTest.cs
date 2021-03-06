﻿using System;
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
            int saltLength = 32;
            int actualLength;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd"))
            {
                actualLength = cipher.Salt.Length;
            }

            Assert.AreEqual(saltLength, actualLength);
        }
        [TestMethod]
        public void ConstructorWithOutParams_InstantiateNewWithRandomSaltAndIV_Pass()
        {
            string passwd = "PassIWantt0youS3";
            string message = "This is my cool message, you fokkin w0t m8";
            string cipherMessage;
            string decrypted;
            byte[] salt;
            byte[] IV;
            using (var cipher = new SymmetricCipher<AesManaged>(passwd, out salt, out IV))
            {
                cipherMessage = cipher.EncryptToString(message);
            }

            using(var cipher = new SymmetricCipher<AesManaged>(passwd, salt, IV))
            {
                decrypted = cipher.DecryptToString(cipherMessage);
            }

            Assert.AreEqual(message, decrypted);
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
        public void EncryptToString_EncryptedPreviouslyDecodedTextBytesAndEncodeItLaterBack_Pass()
        {
            string plainText = "Encrypt me but don' forget me.";
            byte[] plaindata = Encoding.UTF8.GetBytes(plainText);
            string encryptedText;
            byte[] decryptedTextBytes;
            string decryptedText;
            using (var cipher = new SymmetricCipher<AesManaged>("passwd", "mysalt1337"))
            {
                encryptedText = cipher.EncryptToString(plaindata);
                decryptedTextBytes = cipher.Decrypt(encryptedText);
                decryptedText = Encoding.UTF8.GetString(decryptedTextBytes);
            }

            Assert.AreEqual(plainText, decryptedText);
        }
        [TestMethod]
        public void DecryptToString_EncryptAndDecryptToString_Pass()
        {
            string plainText = "Encrypt me but don't forget me.";
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
            byte[] IV;

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44"))
            {
                IV = cipher.IV;
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<AesManaged>("mypasswd2", "mysalt1337bb44", IV))
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
            byte[] IV;

            using (var cipher = new SymmetricCipher<RijndaelManaged>(passwd, salt))
            {
                IV = cipher.IV;
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<RijndaelManaged>(passwd, salt, IV))
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
            byte[] IV;

            using (var cipher = new SymmetricCipher<DESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                IV = cipher.IV;
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<DESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44", IV))
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
            byte[] IV;

            using (var cipher = new SymmetricCipher<RC2CryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                IV = cipher.IV;
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<RC2CryptoServiceProvider>("mypasswd2", "mysalt1337bb44", IV))
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
            byte[] IV;

            using (var cipher = new SymmetricCipher<TripleDESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44"))
            {
                IV = cipher.IV;
                encryptArr = cipher.Encrypt(plainText);
            }

            using (var cipher = new SymmetricCipher<TripleDESCryptoServiceProvider>("mypasswd2", "mysalt1337bb44", IV))
            {
                decryptArr = cipher.Decrypt(encryptArr);
            }

            CollectionAssert.AreEqual(plainTextArr, decryptArr);
        }
        [TestMethod]
        public void Encoding_SetGetEncoding_Pass()
        {
            Encoding setEncoding = Encoding.Unicode;
            Encoding getEncoding;
            using (var mock = new SymmetricCipher<AesManaged>())
            {
                mock.Encoding = Encoding.Unicode;
                getEncoding = mock.Encoding;
            }
            Assert.AreEqual(setEncoding, getEncoding);
        }
        [TestMethod]
        public void HashIterations_SetGetHashIterations_Pass()
        {
            int setHashIterations = 10042;
            int getHashIterations;
            using (var mock = new SymmetricCipher<AesManaged>())
            {
                mock.HashIterations = setHashIterations;
                getHashIterations = mock.HashIterations;
            }
            Assert.AreEqual(setHashIterations, getHashIterations);
        }
        [TestMethod]
        public void SaltAsString_GetSaltAsString_Pass()
        {
            byte[] saltBytes;
            string saltString;
            using (var mock = new SymmetricCipher<AesManaged>("neufreund"))
            {
                saltBytes = mock.Salt;
                saltString = mock.SaltAsString;
            }
            Assert.AreEqual(Convert.ToBase64String(saltBytes), saltString);
        }
        [TestMethod]
        public void IVAsString_GetIVAsString_Pass()
        {
            byte[] ivBytes;
            string ivString;
            using (var mock = new SymmetricCipher<AesManaged>("neufreund"))
            {
                ivBytes = mock.IV;
                ivString = mock.IVAsString;
            }
            Assert.AreEqual(Convert.ToBase64String(ivBytes), ivString);
        }
    }
}
