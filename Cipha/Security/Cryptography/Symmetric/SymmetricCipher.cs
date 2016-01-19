using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Symmetric
{
    public sealed class SymmetricCipher<T> : Cipher
        where T : SymmetricAlgorithm, new()
    {
        SymmetricAlgorithm algo;

        public SymmetricAlgorithm Algorithm
        {
            get { return algo; }
            set 
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                algo = value; 
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
        public SymmetricCipher(byte[] key, byte[] iv)
        {
            algo = new T();
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
        public SymmetricCipher(string password, string salt, int iterations = 1000)
            : this(password, Encoding.UTF8.GetBytes(salt), iterations)
        {        }
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
        public SymmetricCipher(string password, byte[] salt, int iterations = 1000)
        {
            using(DeriveBytes db = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                algo = new T();
                algo.Key = db.GetBytes(algo.KeySize >> 3);
                algo.IV = db.GetBytes(algo.BlockSize >> 3);
            }
            this.salt = salt;
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

        public override CipherConfig ExportConfig()
        {
            return new CipherConfig(algo);
        }
    }
}
