using Cipha.Security.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Symmetric
{
    /// <summary>
    /// Cipher implementation for symmetric algorithms.
    ///  
    /// Algorithms with full support:
    ///     AesManaged
    ///     AesCryptoServiceProvider
    ///     RC2CryptoServiceProvider
    ///     RijndaelManaged
    ///     TrippleDESCryptoServiceProvider
    /// </summary>
    /// <typeparam name="T">The symmetric algorithm.</typeparam>
    public class SymmetricCipher<T> : Cipher
        where T : SymmetricAlgorithm, new()
    {
        // Fields
        protected T algo;

        // Properties
        /// <summary>
        /// The SymmetricAlgorithm which is used for the
        /// cryptographic processes.
        /// </summary>
        public SymmetricAlgorithm Algorithm
        {
            get { return algo; }
            set 
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.GetType() != typeof(T))
                    throw new ArgumentException("value is not of type " + algo.GetType());

                algo = (T)value;
            }
        }

        /// <summary>
        /// Gets or sets the current key size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                return algo.KeySize;
            }
            set
            {
                algo.KeySize = value;
            }
        }

        /// <summary>
        /// Adapts the configuration of the provided algorithm.
        /// </summary>
        /// <param name="symmetricAlgorithm">The algorithm to adapt.</param>
        public SymmetricCipher(T symmetricAlgorithm)
        {
            algo = symmetricAlgorithm;
        }

        /// <summary>
        /// Creates a new instance of the algorithm and sets
        /// its key and iv.
        /// 
        /// Throws CryptographicException if Key of IV has a invalid size.
        /// </summary>
        /// <param name="key">The key to set.</param>
        /// <param name="iv">The IV to set.</param>
        public SymmetricCipher(byte[] key, byte[] iv, int keySize, int blockSize)
        {
            algo = new T();
            algo.KeySize = keySize;
            algo.BlockSize = blockSize;
            algo.Key = key;
            algo.IV = iv;
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// It creates a key with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// </summary>
        /// <param name="password">The password used in the hashing process.</param>
        /// <param name="salt">The salt to use.</param>
        /// <param name="iterations">The iteration count that shall be used in Rfc2898DeriveBytes.</param>
        public SymmetricCipher(string password, string salt, int keysize = 0, int iterations = 10000)
            : this(password, Encoding.UTF8.GetBytes(salt), keysize, iterations)
        {        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// When no salt is specified, a strong, randomly
        /// generated salt will be created with a size
        /// of 64 bytes. After generation, the salt can be 
        /// extracted using the Salt property.
        /// 
        /// It creates a key with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// 
        /// The key size of 0 indicates that the standard 
        /// key size shall be used.
        /// 
        /// Throws:
        ///     ArgumentNullException: pw is null
        ///     CryptographicException: invalid keysize
        /// </summary>
        /// <param name="password">The password used in the hashing process.</param>
        /// <param name="salt">The salt to use.</param>
        /// <param name="iterations">The iteration count that shall be used in Rfc2898DeriveBytes.</param>
        public SymmetricCipher(string password, byte[] salt = null, int keysize = 0, int iterations = 10000)
        {
            if (password == null)
                throw new ArgumentNullException("password");

            algo = new T();
            if (keysize > 0)
                algo.KeySize = keysize;

            this.salt = (salt != null) ? (byte[])salt.Clone() : Utilities.GenerateSalt(DEFAULT_SALT_BYTE_LENGTH);

            GenerateKeys(password, this.salt, iterations);
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// A salt of length x >= 8 is generated.
        /// After generation, the salt can be 
        /// extracted using the Salt property.
        /// 
        /// It creates a key with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// 
        /// The key size of 0 indicates that the standard 
        /// key size shall be used.
        /// 
        /// Throws:
        ///     ArgumentNullException
        ///     ArgumentException
        ///     CryptographicException
        /// </summary>
        /// <param name="password">The password to use.</param>
        /// <param name="saltByteLength">The salt length in bytes. Must be at least 8.</param>
        /// <param name="keysize">The key size. 0 indicates that the default shall be used.</param>
        /// <param name="iterations">The amount of iterations to derive the key.</param>
        public SymmetricCipher(string password, int saltByteLength, int keysize = 0, int iterations = 10000)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            if (saltByteLength < 8)
                throw new ArgumentException("salt must be at least 8 byte");

            algo = new T();
            if (keysize > 0)
                algo.KeySize = keysize;

            
            salt = Utilities.GenerateSalt(saltByteLength);

            GenerateKeys(password, salt, iterations);
        }

        protected override byte[] EncryptData(byte[] plainData)
        {
            using (MemoryStream buffer = new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(buffer, algo.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (StreamWriter writer = new StreamWriter(stream, encoding))
                    {
                        try
                        {
                            writer.Write(Convert.ToBase64String(plainData));
                        }
                        catch(CryptographicException ex)
                        {
                            throw new CryptographicException("encryption failed", ex);
                        }
                    }
                }
                return buffer.ToArray();
            }
        }

        protected override byte[] DecryptData(byte[] cipherData)
        {
            using (MemoryStream buffer = new MemoryStream(cipherData))
            {
                using (CryptoStream stream = new CryptoStream(buffer, algo.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(stream, encoding))
                    {
                        try
                        {
                            return Convert.FromBase64String(reader.ReadToEnd());
                        }
                        catch(CryptographicException ex)
                        {
                            throw new CryptographicException("decryption failed", ex);
                        }
                    }
                }
            }
        }

        protected override void DisposeImplementation(bool disposing)
        {
            if(disposing)
            {
                algo.Dispose();
                algo = null;
            }
        }

        public void GenerateKeys(string password, byte[] salt, int iterationCount)
        {
            using (DeriveBytes db = new Rfc2898DeriveBytes(password, salt, iterationCount))
            {
                algo.Key = db.GetBytes(algo.KeySize >> 3);
                algo.IV = db.GetBytes(algo.BlockSize >> 3);
            }
        }

        public CipherStream<T> CreateStream()
        {
            return new CipherStream<T>(this);
        }
    }
}
