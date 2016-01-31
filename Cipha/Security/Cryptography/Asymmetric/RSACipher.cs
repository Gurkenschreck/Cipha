using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
{
    /// <summary>
    /// RSACipher is a concrete implementation
    /// for the RSA algorithm.
    /// </summary>
    /// <typeparam name="T">Any derivation of RSA.</typeparam>
    public sealed class RSACipher<T> : AsymmetricCipher<T>
        where T : RSA, new()
    {
        bool usefOAEPPadding = true;

        /// <summary>
        /// Instantiates a new instance of the class.
        /// 
        /// If the key size in the parameter is not 0,
        /// it tries to apply the key.
        /// 
        /// The default key size of the algorithms can differ.
        /// Check out the default size via KeySize.
        /// </summary>
        public RSACipher(int keySize = 2048) : base(keySize) { }
        /// <summary>
        /// A constructor which sets the reference of
        /// the algorithm object to the passed object.
        /// </summary>
        /// <param name="rsaAlgorithm">The reference object.</param>
        public RSACipher(T rsaAlgorithm) : base(rsaAlgorithm) { }
        /// <summary>
        /// The constructor accepts the algorithm 
        /// configuration in the xml format.
        /// 
        /// Create the string by using
        /// asymmetricAlgorithm.ToXmlString(exportPrivateKey).
        /// </summary>
        /// <param name="cleartextXmlString">The cleartext algorithm configuration.</param>
        public RSACipher(string cleartextXmlString) : base(cleartextXmlString) { }
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
        public RSACipher(string encryptedXmlString, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
            : base(encryptedXmlString, password, salt, keySize, iterationCount) { }
        
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

        /// <summary>
        /// Encrypts a blob of plain data using
        /// the current RSA algorithm configuration.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted blob of bytes.</returns>
        protected override byte[] EncryptData(byte[] plainData)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).Encrypt(plainData, usefOAEPPadding);
            }
            throw new NotSupportedException("no encryption logic for type " + typeof(T));
        }

        /// <summary>
        /// Decrypts a blob of encrypted data using
        /// the current RSA algorithm configuration.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <returns>The plain blob of bytes.</returns>
        protected override byte[] DecryptData(byte[] cipherData)
        {
            if(algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).Decrypt(cipherData, usefOAEPPadding);
            }
            throw new NotSupportedException("no decryption logic for type " + typeof(T));
        }

        /// <summary>
        /// Signs data using the private key.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="dataToSign">The data to sign.</param>
        /// <returns>The signature.</returns>
        public override byte[] SignData<U>(byte[] dataToSign)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).SignData(dataToSign, new U());
            }
            throw new NotSupportedException("no data signing logic for type " + typeof(T));
        }

        /// <summary>
        /// Verifies a previously signed message to 
        /// check the integrity of it.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="dataToVerify">The data to verify.</param>
        /// <param name="signedData">The existing signature.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).VerifyData(dataToVerify, new U(), signedData);
            }

            throw new NotSupportedException("no verifying logic for type " + typeof(T));
        }

        /// <summary>
        /// Signs a hashed value using the private key.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="hashToSign">The data to sign.</param>
        /// <returns>The signature of the message.</returns>
        public override byte[] SignHash<U>(byte[] hashToSign)
        {
            string hashIdentifier = OIDIdentifier.Get(new U());

            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).SignHash(hashToSign, hashIdentifier);
            }
            throw new NotSupportedException("no hash signing logic for type " + typeof(T));
        }

        /// <summary>
        /// Verifies a previously signed hash to check the integrity
        /// of it.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="hashToVerify">The hash of the message to verify.</param>
        /// <param name="signedHash">The previously signed hash of the message.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public override bool VerifyHash<U>(byte[] hashToVerify, byte[] signedHash)
        {
            string hashIdentifier = OIDIdentifier.Get(new U());

            if(algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).VerifyHash(hashToVerify, hashIdentifier, signedHash);
            }
            
            throw new NotSupportedException("no hash verifying logic for type " + typeof(T));
        }
    }
}
