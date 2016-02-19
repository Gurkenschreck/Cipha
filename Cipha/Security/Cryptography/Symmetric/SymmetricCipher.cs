using Cipha.Security.Cryptography.Hash;
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
    ///     TripleDESCryptoServiceProvider
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
        public T Algorithm
        {
            get { return algo; }
            set 
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.GetType() != typeof(T))
                    throw new ArgumentException("value is not of type " + algo.GetType());

                algo = value;
            }
        }

        /// <summary>
        /// Gets or sets the current plainData size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                return algo.KeySize;
            }
            set
            {
                throw new NotSupportedException("keysize cannot be edited via property");
            }
        }

        /// <summary>
        /// Gets or sets the block size.
        /// </summary>
        public int BlockSize
        {
            get
            {
                return algo.BlockSize;
            }
            set
            {
                algo.BlockSize = value;
            }
        }

        /// <summary>
        /// Gets or sets the plainData.
        /// </summary>
        public byte[] Key
        {
            get
            {
                return algo.Key.Clone() as byte[];
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                if (value.Length == 0)
                    throw new ArgumentException("invalid length");
                algo.Key = (byte[])value.Clone();
            }
        }
        /// <summary>
        /// Gets the current secret plainData as a base64 string.
        /// </summary>
        public string KeyAsString
        {
            get
            {
                return Convert.ToBase64String(algo.Key);
            }
        }

        /// <summary>
        /// Gets or sets the initialize vector (IV).
        /// </summary>
        public byte[] IV
        {
            get { return (byte[])algo.IV.Clone(); }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                algo.IV = (byte[])value.Clone();
            }
        }

        /// <summary>
        /// Gets the IV as a base64 string.
        /// </summary>
        public string IVAsString
        {
            get
            {
                return Convert.ToBase64String(algo.IV);
            }
        }
        

        public SymmetricCipher(int keySize = 0)
        {
            algo = new T();
            if (keySize > 0)
                algo.KeySize = keySize;
            algo.GenerateKey();
            algo.GenerateIV();
        }

        /// <summary>
        /// Adapts the configuration of the provided algorithm.
        /// </summary>
        /// <param name="symmetricAlgorithm">The algorithm to adapt.</param>
        public SymmetricCipher(T symmetricAlgorithm, bool disposeAlgorithm = false)
        {
            algo = symmetricAlgorithm;
            this.disposeAlgorithm = disposeAlgorithm;
        }

        public SymmetricCipher(byte[] key, out byte[] iv, int keySize = 0, int blockSize = 0)
        {
            algo = new T();
            if(keySize > 0)
                algo.KeySize = keySize;
            if(blockSize > 0)
                algo.BlockSize = blockSize;
            algo.Key = (byte[])key.Clone();
            iv = Utilities.GenerateBytes(16);
            algo.IV = (byte[])iv.Clone();
        }
        public SymmetricCipher(byte[] key, int blockSize = 0)
        {
            algo = new T();
            if (blockSize > 0)
                algo.BlockSize = blockSize;
            algo.KeySize = key.Length * 8;
            algo.Key = key.Clone() as byte[];
        }

        /// <summary>
        /// Creates a new instance of the algorithm and sets
        /// its plainData and IV.
        /// 
        /// Throws CryptographicException if Key of IV has a invalid size.
        /// </summary>
        /// <param name="plainData">The plainData to set.</param>
        /// <param name="IV">The IV to set.</param>
        /// <param name="keySize">The plainData size to set.</param>
        /// <param name="blockSize">The size of the blocks to process at once.</param>
        public SymmetricCipher(byte[] key, byte[] iv, int keySize = 0, int blockSize = 0)
        {
            algo = new T();
            if(keySize > 0)
                algo.KeySize = keySize;
            if(blockSize > 0)
                algo.BlockSize = blockSize;
            algo.Key = (byte[])key.Clone();
            algo.IV = (byte[])iv.Clone();
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// It creates a plainData with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// </summary>
        /// <param name="password">The password used in the hashing process.</param>
        /// <param name="salt">The salt to use.</param>
        /// <param name="iterations">The iteration count that shall be used in Rfc2898DeriveBytes.</param>
        public SymmetricCipher(string password, string salt, byte[] IV = null, int keysize = 0, int iterations = 10000)
            : this(password, Encoding.UTF8.GetBytes(salt), IV, keysize, iterations)
        {        }
        public SymmetricCipher(string password, string salt, out byte[] IV, int keysize = 0, int iterations = 10000)
        {
            IV = Utilities.GenerateBytes(16);

            Initialize(password, encoding.GetBytes(salt), iterations, (byte[])IV.Clone(), keysize, 0);
        }

        /// <summary>
        /// Creates a new instance.
        /// 
        /// Returns a salt with the specified salt size in
        /// bytes, or the default salt length of 32 bytes.
        /// 
        /// Returns a random iv.
        /// </summary>
        /// <param name="password">The password to derive the plainData from.</param>
        /// <param name="salt">The salt to help deriving the plainData.</param>
        /// <param name="iv">The initializing vector.</param>
        /// <param name="saltSize">The salt size in bytes.</param>
        /// <param name="iterations">The amount of iterations to derive the plainData.</param>
        public SymmetricCipher(string password, out byte[] salt, out byte[] iv, int saltSize = 0, int iterations = 10000)
        {
            if (saltSize > 0)
                salt = Utilities.GenerateBytes(saltSize);
            else
                salt = Utilities.GenerateBytes(DEFAULT_SALT_BYTE_LENGTH);
                
            iv = Utilities.GenerateBytes(16);
            Initialize(password, (byte[])salt.Clone(), hashIterations, (byte[])iv.Clone(), 0, 0);
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// A salt of length x >= 8 is generated.
        /// After generation, the salt can be 
        /// extracted using the Salt property.
        /// 
        /// It creates a plainData with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// 
        /// The plainData size of 0 indicates that the standard 
        /// plainData size shall be used.
        /// 
        /// Throws:
        ///     ArgumentNullException
        ///     ArgumentException
        ///     CryptographicException
        /// </summary>
        /// <param name="password">The password to use.</param>
        /// <param name="saltByteLength">The salt length in bytes. Must be at least 8.</param>
        /// <param name="keysize">The plainData size. 0 indicates that the default shall be used.</param>
        /// <param name="iterations">The amount of iterations to derive the plainData.</param>
        public SymmetricCipher(string password, int saltByteLength, byte[] IV = null, int keysize = 0, int blockSize = 0, int iterations = 10000)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            if (saltByteLength < 8)
                throw new ArgumentException("salt must be at least 8 byte");

            salt = Utilities.GenerateBytes(saltByteLength);

            Initialize(password, salt, iterations, IV, keysize, blockSize);
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// 
        /// When no salt is specified, a strong, randomly
        /// generated salt will be created with a size
        /// of 64 bytes. After generation, the salt can be 
        /// extracted using the Salt property.
        /// 
        /// It creates a plainData with the password, salt and
        /// iteration count by using the Rfc2898DeriveBytes
        /// implementation of PBKDF2.
        /// 
        /// The plainData size of 0 indicates that the standard 
        /// plainData size shall be used.
        /// 
        /// Throws:
        ///     ArgumentNullException: pw is null
        ///     CryptographicException: invalid keysize
        /// </summary>
        /// <param name="password">The password used in the hashing process.</param>
        /// <param name="salt">The salt to use.</param>
        /// <param name="iterations">The iteration count that shall be used in Rfc2898DeriveBytes.</param>
        public SymmetricCipher(string password, byte[] salt = null, byte[] IV = null, int keysize = 0, int iterations = 10000)
        {
            if (password == null)
                throw new ArgumentNullException("password");

            salt = (salt != null) ? (byte[])salt.Clone() : Utilities.GenerateBytes(DEFAULT_SALT_BYTE_LENGTH);

            Initialize(password, salt, iterations, IV, keysize, 0);
        }


        private void Initialize(string password, byte[] salt, int iterations, byte[] iv, int keysize, int blockSize)
        {
            if (password == null)
                throw new ArgumentNullException("password");

            algo = new T();
            if (keysize > 0)
                algo.KeySize = keysize;

            if (blockSize > 0)
                algo.BlockSize = blockSize;

            this.salt = salt;

            DeriveKey(password, this.salt, iterations);

            if (iv == null)
                algo.IV = Utilities.GenerateBytes(algo.BlockSize >> 3);
            else
                algo.IV = iv;
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
                if(disposeAlgorithm)
                    algo.Dispose();
                algo = null;
            }
        }

        public void DeriveKey(string password, byte[] salt, int iterationCount)
        {
            using (DeriveBytes db = new Rfc2898DeriveBytes(password, salt, iterationCount))
            {
                algo.Key = db.GetBytes(algo.KeySize >> 3);
            }
        }

        public CipherStream<T> CreateStream()
        {
            return new CipherStream<T>(this);
        }
        public HMACer<U> CreateHMACer<U>()
            where U : KeyedHashAlgorithm, new()
        {
            return new HMACer<U>(algo.Key);
        }
    }
}
