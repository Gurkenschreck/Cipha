using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public abstract class Cipher : IDisposable
    {
        //Properties
        protected int hashIterations = 1000;
        /// <summary>
        /// The amount of iterations used in the key
        /// derivation process.
        /// 
        /// Default:
        ///     1000
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

        protected Encoding encoding = Encoding.UTF8;
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

        protected byte[] salt;

        public byte[] Salt
        {
            get { return salt; }
            set { salt = value; }
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

        public virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                hashIterations = 0;
                encoding = Encoding.ASCII;
                encoding = null;
                Utilities.SetArrayValuesZero(salt);
                salt = null;
            }

            DisposeImplementation(disposing);
        }

        /// <summary>
        /// Encrypts a rgb using the algorithm.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plainData)
        {
            return EncryptData(plainData);
        }

        /// <summary>
        /// Encrypts a string using the algorithm.
        /// 
        /// Specify the character encoding with the
        /// Encoding property of this class.
        /// </summary>
        /// <param name="plainString">The string to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        public byte[] Encrypt(string plainString)
        {
            return EncryptData(encoding.GetBytes(plainString));
        }

        /// <summary>
        /// Decrypts a rgb using the algorithm.
        /// </summary>
        /// <param name="cipherData">The string to decrypt.</param>
        /// <returns>The original data.</returns>
        public byte[] Decrypt(byte[] cipherData)
        {
            return DecryptData(cipherData);
        }

        /// <summary>
        /// Decrypts a string using the algorithm.
        /// 
        /// Specify the character encoding with the
        /// Encoding property of this class.
        /// </summary>
        /// <param name="cipherString">The string to decrypt.</param>
        /// <returns>The decrypted string.</returns>
        public byte[] Decrypt(string cipherString)
        {
            return DecryptData(Convert.FromBase64String(cipherString));
        }

        /// <summary>
        /// Encrypts a rgb using the algorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data represented as a string.</returns>
        public string EncryptToString(byte[] plainData)
        {
            return Convert.ToBase64String(EncryptData(plainData));
        }

        /// <summary>
        /// Encrypts a rgb using the algorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// </summary>
        /// <param name="plainString">The plain string.</param>
        /// <returns>The encrypted string represented as a string.</returns>
        public string EncryptToString(string plainString)
        {
            return Convert.ToBase64String(EncryptData(encoding.GetBytes(plainString)));
        }

        /// <summary>
        /// Decrypts a rgb using the algorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <returns>The decrypted data represented as a string.</returns>
        public string DecryptToString(byte[] cipherData)
        {
            return Convert.ToBase64String(DecryptData(cipherData));
        }

        /// <summary>
        /// Decrypts a string using the algorithm.
        /// 
        /// The used character encoding is specified
        /// via the Encoding property.
        /// </summary>
        /// <param name="cipherString">The encrypted string.</param>
        /// <returns>The decrypted string.</returns>
        public string DecryptToString(string cipherString)
        {
            return encoding.GetString(DecryptData(Convert.FromBase64String(cipherString)));
        }

        // Implementations of the encryption process.
        /// <summary>
        /// The specific encryption implementation.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        protected abstract byte[] EncryptData(byte[] plainData);

        /// <summary>
        /// The specific decryption implementation.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        protected abstract byte[] DecryptData(byte[] cipherData);

        /// <summary>
        /// This method is used inside the Dispose method of
        /// the base class.
        /// Dispose every ressource which is derivate specific.
        /// </summary>
        /// <param name="disposing">If the Dispose call has been made by the client.</param>
        protected abstract void DisposeImplementation(bool disposing);

        /// <summary>
        /// When overwritten, it returns a new CipherConfig object.
        /// 
        /// This config contains all information used in this
        /// algorithm for later use or key exchange.
        /// </summary>
        /// <returns>The new CipherConfig.</returns>
        public abstract CipherConfig ExportConfig();
    }
}
