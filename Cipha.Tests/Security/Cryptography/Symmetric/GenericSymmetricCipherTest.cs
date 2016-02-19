using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;
using Cipha.Security.Cryptography.Symmetric;

namespace Cipha.Tests.Security.Cryptography.Symmetric
{
    [TestClass]
    public class GenericSymmetricCipherTest
    {
        /// <summary>
        /// Compares the methods of encrypting a string
        /// and a byte array.
        /// </summary>
        [TestMethod]
        public void Aes256BasicCipher1_SameInstance_CompareOutput()
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
            d.Encoding = Encoding.Default;

            encryptedPlainData = d.Encrypt(plDt, password, salt);
            encryptedPlainDataAsString = Convert.ToBase64String(encryptedPlainData);
            encryptedPlainDataAsString2 = d.EncryptToString(plainData, password, salt);
        }

        /// <summary>
        /// Encrypts and decrypts a byte array.
        /// </summary>
        [TestMethod]
        public void Aes256BasicCipher2_SameInstance_CompareOutput()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();

            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] saltBytes = d.Encoding.GetBytes(salt);
            byte[] encrypted;
            byte[] decrypted;
            string decryptedString;

            encrypted = d.Encrypt(plDt, password, salt);
            decrypted = d.Decrypt(encrypted, password, saltBytes);

            decryptedString = d.Encoding.GetString(decrypted);

            Assert.AreEqual(plainData, decryptedString);
        }

        /// <summary>
        /// 
        /// </summary>
        [TestMethod]
        public void Aes128BasicCipher_SameInstance_CompareOutput()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();
            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] saltBytes = d.Encoding.GetBytes(salt);
            byte[] encrypted;
            byte[] decrypted;
            string decryptedString;

            d.KeySize = 128;
            encrypted = d.Encrypt(plDt, password, salt);
            decrypted = d.Decrypt(encrypted, password, saltBytes);

            decryptedString = d.Encoding.GetString(decrypted);

            Assert.AreEqual(plainData, decryptedString);
        }

        [TestMethod]
        public void Aes256BasicCipher_MultiInstance_CompareOutput()
        {
            GenericSymmetricCipher<AesManaged> cipherA = new GenericSymmetricCipher<AesManaged>();
            GenericSymmetricCipher<AesManaged> cipherB = new GenericSymmetricCipher<AesManaged>();

            string plainMessage = "Encrypt me!";
            string encryptedMessage;
            string decryptedMessage;
            string password = "thisismypass447";
            string salt = "k;dwa.r3-146;:##+$";

            encryptedMessage = cipherA.EncryptToString(plainMessage, password, salt);

            decryptedMessage = cipherB.DecryptToString(encryptedMessage, password, salt);

            Assert.AreEqual(plainMessage, decryptedMessage);
        }

        /// <summary>
        /// Tries to encrypt a string using a 127 bit plainData.
        /// 
        /// Expecting a CryptographicException because
        /// an Aes plainData cannot have the size of 127.
        /// </summary>
        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void Aes127ChangeKeySize_SameInstance_InvalidKeySizeFail()
        {
            GenericSymmetricCipher<AesManaged> d = new GenericSymmetricCipher<AesManaged>();
            string plainData = "Hello my friends...";
            byte[] plDt = d.Encoding.GetBytes(plainData);
            string password = "mySecure4,;..PW";
            string salt = "44qdbcdef;;53#";
            byte[] encrypted;

            d.KeySize = 129;
            encrypted = d.Encrypt(plDt, password, salt);
        }
    }
}
