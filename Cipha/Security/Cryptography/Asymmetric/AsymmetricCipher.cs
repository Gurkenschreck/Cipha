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
    public sealed class AsymmetricCipher<T> : Cipher
        where T : AsymmetricAlgorithm, new()
    {
        // Fields
        T algo = new T();
        bool usefOAEPPadding = true;

        //Properties
        public AsymmetricAlgorithm Algorithm
        {
            get { return algo; }
            set 
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if(value.GetType() == typeof(T))
                    algo = (T)value;

                throw new ArgumentException("value is not of type " + algo.GetType());
            }
        }

        /// <summary>
        /// fOAEP is a padding which can be used
        /// by the RSACryptoServiceProvider.
        /// 
        /// Default:
        ///     true
        /// </summary>
        public bool UsefOAEPPadding
        {
            get { return usefOAEPPadding; }
            set { usefOAEPPadding = value; }
        }


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
        /// The most simple constructor which is setting
        /// the key size of the algorithm to 2048.
        /// </summary>
        public AsymmetricCipher()
            :this(2048)
        {        }

        /// <summary>
        /// The constructor which accepts the
        /// key size to use for the processes.
        /// </summary>
        /// <param name="keySize">The key size in bits.</param>
        public AsymmetricCipher(int keySize)
        {
            algo.KeySize = keySize;
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
        public string ToXmlString(bool includePrivateKey)
        {
            return algo.ToXmlString(includePrivateKey);
        }

        /// <summary>
        /// Applies the given encryptedXmlString to the current
        /// object.
        /// </summary>
        /// <param name="encryptedXmlString">The xml configuration string.</param>
        public void FromXmlString(string xmlString)
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
        public string ToEncryptedXmlString<U>(bool includePrivateKey, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            using(var symAlgo = new SymmetricCipher<U>(password, salt, keySize, iterationCount))
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
        public void FromEncryptedXmlString<U>(string encryptedXmlString, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new ()
        {
            using(var symAlgo = new SymmetricCipher<U>(password, salt, keySize, iterationCount))
            {
                algo.FromXmlString(symAlgo.DecryptToString(encryptedXmlString));
            }
        }


        protected override byte[] EncryptData(byte[] plainData)
        {
            if(algo is RSA)
            {
                if(algo is RSACryptoServiceProvider)
                {
                    return (algo as RSACryptoServiceProvider).Encrypt(plainData, usefOAEPPadding);
                }
            }
            throw new NotSupportedException(string.Format("algo of type {0} does not support encryption", typeof(T)));
        }

        protected override byte[] DecryptData(byte[] cipherData)
        {
            if(algo is RSA)
            {
                return (algo as RSACryptoServiceProvider).Decrypt(cipherData, true);
            }
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

        public override CipherConfig ExportConfig()
        {
            throw new NotImplementedException();
        }
    }
}
