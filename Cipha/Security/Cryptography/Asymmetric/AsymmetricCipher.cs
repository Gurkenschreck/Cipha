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
        protected T algo;

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
        /// Gets or sets the plainData size of the algorithm.
        /// 
        /// When it sets, a new instance of T is created with
        /// the new plainData size.
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
        /// The default plainData size of the algorithms can differ.
        /// Check out the default size via KeySize.
        /// 
        /// To set a different plainData size, use the
        /// AsymmetricCipher(T asymmetricAlgorithm)
        /// constructor with new T(int keySize)
        /// </summary>
        public AsymmetricCipher(int keySize = 0)
        {
            if (keySize > 0)
                algo = (T)Activator.CreateInstance(typeof(T), keySize);
            else
                algo = new T();
        }

        /// <summary>
        /// A constructor which sets the reference of
        /// the algorithm object to the passed object.
        /// </summary>
        /// <param name="asymmetricAlgorithm">The reference object.</param>
        public AsymmetricCipher(T asymmetricAlgorithm, bool disposeAlgorithm = false)
        {
            algo = asymmetricAlgorithm;
            this.disposeAlgorithm = disposeAlgorithm;
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
            algo = new T();
            algo.FromXmlString(cleartextXmlString);
        }

        /// <summary>
        /// Constructor to adapt an already existing 
        /// configuration in the xml format.
        /// 
        /// The encryptedPublicKeyXmlString will be decrypted using AES256.
        /// A possible workaround is to instantiate the
        /// symmetricCipher and call the FromEncryptedXmlString.
        /// </summary>
        /// <param name="encryptedPublicKeyXmlString">The encrypted encryptedPublicKeyXmlString.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keySize">The plainData size used in the encryption process.</param>
        /// <param name="iterationCount">The amount of iterations to derive the plainData.</param>
        public AsymmetricCipher(string encryptedXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int iterationCount = 10000)
        {
            algo = new T();
            FromEncryptedXmlString<AesManaged>(encryptedXmlString, password, salt, IV, keySize, iterationCount);
        }

        /// <summary>
        /// Exports the current configuration as plaintext 
        /// in xml format.
        /// </summary>
        /// <param name="includePrivateKey">If the exported configuration should include the private plainData.</param>
        /// <returns>The plain configuration string.</returns>
        public virtual string ToXmlString(bool includePrivateKey)
        {
            return algo.ToXmlString(includePrivateKey);
        }

        /// <summary>
        /// Applies the given encryptedPublicKeyXmlString to the current
        /// object.
        /// </summary>
        /// <param name="encryptedPublicKeyXmlString">The xml configuration string.</param>
        public virtual void FromXmlString(string xmlString)
        {
            algo.FromXmlString(xmlString);
        }
        
        /// <summary>
        /// Makes use of the SymmetricCipher to encrypt
        /// the current encryptedPublicKeyXmlString configuration using
        /// at least a password and salt.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <typeparam name="U">The symmetric algorithm to use for the encryption.</typeparam>
        /// <param name="includePrivateKey">Specifies if the encrypted xml config should include the private plainData.</param>
        /// <param name="password">The password to encrypt it.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keySize">The plainData size to use.</param>
        /// <param name="iterationCount">The amount of iterations to derive the plainData.</param>
        /// <returns></returns>
        public virtual string ToEncryptedXmlString<U>(bool includePrivateKey, string password, byte[] salt, out byte[] IV, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            this.salt = (byte[])salt.Clone();
            
            using(var symAlgo = new SymmetricCipher<U>(password, this.salt, null, keySize, iterationCount))
            {
                IV = (byte[])symAlgo.IV.Clone();
                return symAlgo.EncryptToString(algo.ToXmlString(includePrivateKey));
            }
        }

        /// <summary>
        /// Makes use of the SymmetricCipher to decrypt
        /// the given encryptedPublicKeyXmlString configuration using
        /// at least a password and salt.
        /// 
        /// Throws:
        ///     CryptographicException
        /// </summary>
        /// <typeparam name="U">The symmetric algorithm that was used in the encryption process.</typeparam>
        /// <param name="encryptedPublicKeyXmlString">The encrypted plainXmlString.</param>
        /// <param name="password">The password to decrypt it.</param>
        /// <param name="salt">The salt used in the encryption process.</param>
        /// <param name="keySize">THe plainData size to use.</param>
        /// <param name="iterationCount">The amount of iterations to derive the plainData.</param>
        public virtual void FromEncryptedXmlString<U>(string encryptedXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int blockSize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            using(var symAlgo = new SymmetricCipher<U>(password, salt, IV, keySize, iterationCount))
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
                if(disposeAlgorithm)
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
        /// with the private plainData.
        /// Signed data can later be verified by
        /// encrypting it with the public plainData.
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
        /// private plainData used in the signing process.
        /// </summary>
        /// <typeparam name="U">The same hash algorithm used in the signing process.</typeparam>
        /// <param name="dataToVerify">The plain data to verify its integrity.</param>
        /// <param name="signedData">The already signed data to check.</param>
        /// <returns>If the data has not been tampered with.</returns>
        public abstract bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
            where U : HashAlgorithm, new();

        /// <summary>
        /// Signs a already existing hash.
        /// </summary>
        /// <param name="hashToSign">The pre calculated hash to sign.</param>
        /// <returns>The signed hash.</returns>
        public abstract byte[] SignHash(byte[] hashToSign);

        /// <summary>
        /// Hashes the data with a new instance of U
        /// and signs it.
        /// </summary>
        /// <typeparam name="U">The hash to use for signing.</typeparam>
        /// <param name="dataToSign">The data to create a hash from and sign it.</param>
        /// <returns>The signed hash value calculated from dataToSign.</returns>
        public virtual byte[] ComputeAndSignHash<U>(byte[] dataToSign)
            where U : HashAlgorithm, new()
        {
            return SignHash(new U().ComputeHash(dataToSign));
        }

        /// <summary>
        /// Verifies the two already existing hashes.
        /// </summary>
        /// <param name="hashToVerify">The hash of the original data.</param>
        /// <param name="signedHash">The signed hash.</param>
        /// <returns></returns>
        public abstract bool VerifyHash(byte[] hashToVerify, byte[] signedHash);

        /// <summary>
        /// Verifies a previously signed hash to check the integrity
        /// of it.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="dataToVerify">The hash of the message to verify.</param>
        /// <param name="signedHash">The previously signed hash of the message.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public virtual bool ComputeAndVerifyHash<U>(byte[] dataToVerify, byte[] signedHash)
            where U : HashAlgorithm, new()
        {
            return VerifyHash(new U().ComputeHash(dataToVerify), signedHash);
        }

        /// <summary>
        /// Hashes the string and signs it.
        /// </summary>
        /// <typeparam name="U">The hashing algorithm to use.</typeparam>
        /// <param name="message">The plain message to sign.</param>
        /// <returns>The signature of the message as a base64 string.</returns>
        public string SignStringToString<U>(string message)
            where U : HashAlgorithm, new()
        {
            return Convert.ToBase64String(ComputeAndSignHash<U>(encoding.GetBytes(message)));
        }

        /// <summary>
        /// Hashes the original message, signs it and 
        /// compares it to the provided signature.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="originalMessage">The original message sent.</param>
        /// <param name="signature">The asserted signature base64.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public bool VerifyString<U>(string originalMessage, string signature)
            where U : HashAlgorithm, new()
        {
            return ComputeAndVerifyHash<U>(encoding.GetBytes(originalMessage), Convert.FromBase64String(signature));
        }
    }
}
