﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public abstract class Cipher : IDisposable
    {
        //Properties
        protected int hashIterations = 10000;
        protected Encoding encoding = Encoding.UTF8;
        protected byte[] salt;
        protected static int DEFAULT_SALT_BYTE_LENGTH = 32;
        protected bool disposeAlgorithm = true;

        /// <summary>
        /// The amount of iterations used in the plainData
        /// derivation process.
        /// 
        /// Default:
        ///     10000
        /// </summary>
        public int HashIterations
        {
            get { return hashIterations; }
            set 
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException("hashiterations cannot be less than 1");

                hashIterations = value; 
            }
        }

        /// <summary>
        /// The encoding with which the strings are converted.
        /// 
        /// Default:
        ///     Encoding.UTF8
        /// </summary>
        public Encoding Encoding
        {
            get { return encoding; }
            set { encoding = value; }
        }

        /// <summary>
        /// The salt used in the password derivation process.
        /// 
        /// Returns null if no salt was previously used.
        /// 
        /// Default:
        ///     null
        /// </summary>
        public byte[] Salt
        {
            get 
            {
                if(salt != null)
                    return (byte[])salt.Clone();
                return null;
            }
        }

        /// <summary>
        /// The salt used in the password derivation process
        /// represented as a base64 string.
        /// </summary>
        public string SaltAsString
        {
            get
            {
                if(salt != null)
                    return Convert.ToBase64String(salt);
                return null;
            }
        }

        /// <summary>
        /// Gets or sets the used plainData size.
        /// </summary>
        public abstract int KeySize
        {
            get;
            set;
        }

        // destructor
        ~Cipher()
        {
            Dispose(false);
        }
        
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            try
            {
                // First dispose child
                DisposeImplementation(disposing);
            }
            finally
            {
                // then base
                if (disposing)
                {
                    hashIterations = 0;
                    encoding = Encoding.ASCII;
                    encoding = null;
                    if (salt != null)
                        Utilities.SetArrayValuesZero(salt);
                    salt = null;
                }
            }
        }
        
        /// <summary>
        /// Encrypts a rgb using the cngAlgorithm.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plainData)
        {
            return EncryptData(plainData);
        }

        /// <summary>
        /// Encrypts a string using the cngAlgorithm.
        /// 
        /// Specify the character encoding with the
        /// Encoding property of this class.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="plainData">The string to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        public byte[] Encrypt(string plainString)
        {
            return EncryptData(encoding.GetBytes(plainString));
        }

        /// <summary>
        /// Decrypts a rgb using the cngAlgorithm.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="cipherData">The string to decrypt.</param>
        /// <returns>The original data.</returns>
        public byte[] Decrypt(byte[] cipherData)
        {
            return DecryptData(cipherData);
        }

        /// <summary>
        /// Decrypts a string using the cngAlgorithm.
        /// 
        /// Specify the character encoding with the
        /// Encoding property of this class.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="cipherData">The string to decrypt.</param>
        /// <returns>The decrypted string.</returns>
        public byte[] Decrypt(string cipherString)
        {
            return DecryptData(Convert.FromBase64String(cipherString));
        }

        /// <summary>
        /// Encrypts a rgb using the cngAlgorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data represented as a string.</returns>
        public string EncryptToString(byte[] plainData)
        {
            return Convert.ToBase64String(EncryptData(plainData));
        }

        /// <summary>
        /// Encrypts a rgb using the cngAlgorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="plainData">The plain string.</param>
        /// <returns>The encrypted string represented as a string.</returns>
        public string EncryptToString(string plainString)
        {
            return EncryptToString(encoding.GetBytes(plainString));
        }

        /// <summary>
        /// Decrypts a rgb using the cngAlgorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <returns>The decrypted data represented as a base64 string.</returns>
        public string DecryptToString(byte[] cipherData)
        {
            return encoding.GetString(DecryptData(cipherData));
        }

        /// <summary>
        /// Decrypts a string using the cngAlgorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="cipherData">The encrypted string.</param>
        /// <returns>The decrypted string.</returns>
        public string DecryptToString(string cipherString)
        {
            return DecryptToString(Convert.FromBase64String(cipherString));
        }

        // Implementations of the encryption process.
        /// <summary>
        /// The specific encryption implementation.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        protected abstract byte[] EncryptData(byte[] plainData);

        /// <summary>
        /// The specific decryption implementation.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        protected abstract byte[] DecryptData(byte[] cipherData);

        /// <summary>
        /// This method is used inside the Dispose method of
        /// the base class.
        /// Dispose every ressource which is derivate specific.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <param name="disposing">If the Dispose call has been made by the client.</param>
        protected abstract void DisposeImplementation(bool disposing);
    }
}
