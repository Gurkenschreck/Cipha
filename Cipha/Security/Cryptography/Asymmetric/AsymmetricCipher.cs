using Cipha.Security.Cryptography.Symmetric;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
{
    /// <summary>
    /// Cipher implementation for asymmetric algorithms.
    /// 
    /// All AsymmetricAlgorithms are in general 
    /// partially-supported.
    /// 
    /// Algorithms with full support:
    ///     RSACryptoServiceProvider
    /// </summary>
    /// <typeparam name="T">The asymmetric algorithm.</typeparam>
    public abstract class AsymmetricCipher<T> : Cipher
        where T : AsymmetricAlgorithm, new()
    {
        // Fields
        protected T algo = new T();

        //Properties
        /// <summary>
        /// Gets or sets the current instance.
        /// </summary>
        public T Algorithm
        {
            get { return algo; }
            set 
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if(value.GetType() == typeof(T))
                {
                    algo = (T)value;
                    return;
                }

                throw new ArgumentException("value is not of type " + algo.GetType());
            }
        }

        /// <summary>
        /// Gets or sets the key size of the algorithm.
        /// 
        /// When it sets, a new instance of T is created with
        /// the new key size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                return algo.KeySize;
            }
            set
            {
                using (var tempAlgo = (T)Activator.CreateInstance(typeof(T), (int)value))
                {
                    algo.FromXmlString(tempAlgo.ToXmlString(true));
                }
            }
        }

        /// <summary>
        /// Instantiates a new instance of the class.
        /// 
        /// The default key size of the algorithms can differ.
        /// Check out the default size via KeySize.
        /// 
        /// To set a different key size, use the
        /// AsymmetricCipher(T asymmetricAlgorithm)
        /// constructor with new T(int keySize)
        /// </summary>
        public AsymmetricCipher(int keySize = 0)
        {
            if (keySize != 0)
                KeySize = keySize;
        }

        /// <summary>
        /// A constructor which sets the reference of
        /// the algorithm object to the passed object.
        /// </summary>
        /// <param name="asymmetricAlgorithm">The reference object.</param>
        public AsymmetricCipher(T asymmetricAlgorithm)
        {
            algo = asymmetricAlgorithm;
        }

        /// <summary>
        /// The constructor accepts the algorithm 
        /// configuration in the xml format.
        /// 
        /// Create the string by using
        /// asymmetricAlgorithm.ToXmlString(exportPrivateKey).
        /// </summary>
        /// <param name="cleartextXmlString">The cleartext algorithm configuration.</param>
        public AsymmetricCipher(string cleartextXmlString)
        {
            algo.FromXmlString(cleartextXmlString);
        }

        /// <summary>
        /// Constructor to adapt an already existing 
        /// configuration in the xml format.
        /// 
        /// The encryptedXmlString will be decrypted using AES256.
        /// A possible workaround is to instantiate the
        /// cipher and call the FromEncryptedXmlString.
        /// </summary>
        /// <param name="encryptedXmlString">The encrypted encryptedXmlString.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keySize">The key size used in the encryption process.</param>
        /// <param name="iterationCount">The amount of iterations to derive the key.</param>
        public AsymmetricCipher(string encryptedXmlString, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
        {
            FromEncryptedXmlString<AesManaged>(encryptedXmlString, password, salt, keySize, iterationCount);
        }

        /// <summary>
        /// Exports the current configuration as plaintext 
        /// in xml format.
        /// </summary>
        /// <param name="includePrivateKey">If the exported configuration should include the private key.</param>
        /// <returns>The plain configuration string.</returns>
        public virtual string ToXmlString(bool includePrivateKey)
        {
            return algo.ToXmlString(includePrivateKey);
        }

        /// <summary>
        /// Applies the given encryptedXmlString to the current
        /// object.
        /// </summary>
        /// <param name="encryptedXmlString">The xml configuration string.</param>
        public virtual void FromXmlString(string xmlString)
        {
            algo.FromXmlString(xmlString);
        }
        
        /// <summary>
        /// Makes use of the SymmetricCipher to encrypt
        /// the current encryptedXmlString configuration using
        /// at least a password and salt.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <typeparam name="U">The symmetric algorithm to use for the encryption.</typeparam>
        /// <param name="includePrivateKey">Specifies if the encrypted xml config should include the private key.</param>
        /// <param name="password">The password to encrypt it.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keySize">The key size to use.</param>
        /// <param name="iterationCount">The amount of iterations to derive the key.</param>
        /// <returns></returns>
        public virtual string ToEncryptedXmlString<U>(bool includePrivateKey, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            using(var symAlgo = new SymmetricCipher<U>(password, (byte[])salt.Clone()))
            {
                return symAlgo.EncryptToString(algo.ToXmlString(includePrivateKey));
            }
        }

        /// <summary>
        /// Makes use of the SymmetricCipher to decrypt
        /// the given encryptedXmlString configuration using
        /// at least a password and salt.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <typeparam name="U">The symmetric algorithm that was used in the encryption process.</typeparam>
        /// <param name="encryptedXmlString">The encrypted plainXmlString.</param>
        /// <param name="password">The password to decrypt it.</param>
        /// <param name="salt">The salt used in the encryption process.</param>
        /// <param name="keySize">THe key size to use.</param>
        /// <param name="iterationCount">The amount of iterations to derive the key.</param>
        public virtual void FromEncryptedXmlString<U>(string encryptedXmlString, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            using(var symAlgo = new SymmetricCipher<U>(password, (byte[])salt.Clone(), keySize, iterationCount))
            {
                algo.FromXmlString(symAlgo.DecryptToString(encryptedXmlString));
            }
        }

        /// <summary>
        /// Encrypts a blob of plain data using the
        /// current configuration.
        /// 
        /// Encrypted supported for RSACryptoServiceProvider.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        protected override byte[] EncryptData(byte[] plainData)
        {
            throw new NotSupportedException(string.Format("algo of type {0} does not support encryption", typeof(T)));
        }

        /// <summary>
        /// Decrypts a blob of encrypted data.
        /// </summary>
        /// <param name="cipherData">The encrypted blob.</param>
        /// <returns>The decrypted data.</returns>
        protected override byte[] DecryptData(byte[] cipherData)
        {
            throw new NotSupportedException(string.Format("algo of type {0} does not support decryption", typeof(T)));
        }

        /// <summary>
        /// Dispose custom ressources.
        /// </summary>
        /// <param name="disposing">If the method is called by the client.</param>
        protected override void DisposeImplementation(bool disposing)
        {
            if(disposing)
            {
                algo.Dispose();
                algo = null;
            }
        }

        /// <summary>
        /// Signs a blob of bytes with the current
        /// algorithm.
        /// 
        /// In the signing process needs a hash
        /// algorithm to do its magic.
        /// 
        /// Signing data encrypts the plain data
        /// with the private key.
        /// Signed data can later be verified by
        /// encrypting it with the public key.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="dataToSign">The plain data to sign.</param>
        /// <returns>The signature of the blob.</returns>
        public abstract byte[] SignData<U>(byte[] dataToSign)
            where U : HashAlgorithm, new();

        /// <summary>
        /// Checks the integrity of the plain message.
        /// 
        /// The dataToVerify is encrypted using the same
        /// private key used in the signing process.
        /// </summary>
        /// <typeparam name="U">The same hash algorithm used in the signing process.</typeparam>
        /// <param name="dataToVerify">The plain data to verify its integrity.</param>
        /// <param name="signedData">The already signed data to check.</param>
        /// <returns>If the data has not been tampered with.</returns>
        public abstract bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
            where U : HashAlgorithm, new();


        /// <summary>
        /// Creates a signature for the specified pre-calculated 
        /// hash value.
        /// 
        /// Some hash identifier can be found in the
        /// OIDIdentifier class.
        /// </summary>
        /// <param name="hashToSign">The hash to sign.</param>
        /// <returns>The signature of the hash.</returns>
        public abstract byte[] SignHash<U>(byte[] hashToSign)
            where U : HashAlgorithm, new();

        /// <summary>
        /// Verifies a previously signed hash to check the integrity
        /// of it.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="hashToVerify">The hash of the message to verify.</param>
        /// <param name="signedHash">The previously signed hash of the message.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public abstract bool VerifyHash<U>(byte[] hashToVerify, byte[] signedHash)
            where U : HashAlgorithm, new();
    }
}
