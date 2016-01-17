using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace Cipha.Tests.Security.Cryptography.Symmetric
{
    [TestClass]
    public class GenericSymmetricCipherTests
    {
        /// <summary>
        /// Compares the methods of encrypting a string
        /// and a byte array.
        /// </summary>
        [TestMethod]
        public void CompareAes256Encryption()
        {
            // Compare the Encrypt(string...) and Encrypt(byte[]..) outputs
            string plainData = "Hello my friends...";
            byte[] plDt = Encoding.Default.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] encryptedPlainData;
            string encryptedPlainDataAsString;
            string encryptedPlainDataAsString2;
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();


            encryptedPlainData = d.Encrypt(plDt, password, salt);
            encryptedPlainDataAsString = Encoding.Default.GetString(encryptedPlainData);
            encryptedPlainDataAsString2 = d.Encrypt(plainData, password, salt);

            Assert.AreEqual(encryptedPlainDataAsString, encryptedPlainDataAsString2);
        }

        /// <summary>
        /// Encrypts and decrypts a byte array.
        /// </summary>
        [TestMethod]
        public void CheckAes256Encryption()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();

            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] encrypted;
            byte[] decrypted;
            string decryptedString;

            encrypted = d.Encrypt(plDt, password, salt);
            decrypted = d.Decrypt(encrypted, password, salt);

            decryptedString = d.Encoding.GetString(decrypted);

            Assert.AreEqual(plainData, decryptedString);
        }

        /// <summary>
        /// 
        /// </summary>
        [TestMethod]
        public void Aes128Encryption()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();
            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] encrypted;
            byte[] decrypted;
            string decryptedString;

            d.KeySize = 128;
            encrypted = d.Encrypt(plDt, password, salt);
            decrypted = d.Decrypt(encrypted, password, salt);

            decryptedString = d.Encoding.GetString(decrypted);

            Assert.AreEqual(plainData, decryptedString);
        }

        /// <summary>
        /// Tries to encrypt a string using a 127 bit key.
        /// 
        /// Expecting a CryptographicException because
        /// an Aes key cannot have the size of 127.
        /// </summary>
        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void Aes127EncryptionFails()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();
            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] encrypted;

            d.KeySize = 127;
            encrypted = d.Encrypt(plDt, password, salt);
        }
    }
}
