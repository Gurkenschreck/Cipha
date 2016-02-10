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
        public RSACipher(string encryptedXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int iterationCount = 10000)
            : base(encryptedXmlString, password, salt, IV, keySize, iterationCount) { }
        
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
            return algo.EncryptValue(plainData);
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
            return algo.DecryptValue(cipherData);
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
            if(algo is ISigner)
            {
                return (algo as ISigner).SignData(dataToSign);
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
            if(algo is ISigner)
            {
                return (algo as ISigner).VerifyData(dataToVerify, signedData);
            }
            throw new NotSupportedException("no verifying logic for type " + typeof(T));
        }

        /// <summary>
        /// Signs a SHA256 hash using the private key.
        /// </summary>
        /// <param name="dataToSign">The data to sign.</param>
        /// <returns>The signature of the message.</returns>
        public override byte[] SignHash(byte[] hashToSign)
        {
            return SignHash(hashToSign, "SHA256");
        }
        public byte[] SignHash(byte[] hashToSign, HashAlg hashOID)
        {
            return SignHash(hashToSign, OIDIdentifier.Get(hashOID));
        }
        public byte[] SignHash(byte[] hashToSign, HashAlgorithm hashAlgo)
        {
            return SignHash(hashToSign, OIDIdentifier.Get(hashAlgo));
        }

        public byte[] SignHash(byte[] hashToSign, string hashOID)
        { // IMPE
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).SignHash(hashToSign, hashOID);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).SignHash(hashToSign);
            }
            throw new NotSupportedException("no hash signing logic for type " + typeof(T));
        }

        /// <summary>
        /// Signs data using algorithm U.
        /// </summary>
        /// <typeparam name="U">The algorithm used in the hashing process.</typeparam>
        /// <param name="dataToSign">The original message.</param>
        /// <returns>The signed hash.</returns>
        public override byte[] ComputeAndSignHash<U>(byte[] dataToSign)
        {
            return SignHash(new U().ComputeHash(dataToSign), OIDIdentifier.Get(new U()));
        }

        /// <summary>
        /// Verifies a SHA256 hash byt comparing it to the
        /// already signed data.
        /// </summary>
        /// <param name="hashToVerify">The SHA256 hash of the data.</param>
        /// <param name="signedHash">The already signed SHA256 hash.</param>
        /// <returns></returns>
        public override bool VerifyHash(byte[] hashToVerify, byte[] signedHash)
        {
            return VerifyHash(hashToVerify, "SHA256", signedHash);
        }
        public bool VerifyHash(byte[] hashToVerify, HashAlg algo, byte[] signedHash)
        {
            return VerifyHash(hashToVerify, OIDIdentifier.Get(algo), signedHash);
        }
        public bool VerifyHash(byte[] hashToVerify, HashAlgorithm algo, byte[] signedHash)
        {
            return VerifyHash(hashToVerify, OIDIdentifier.Get(algo), signedHash);
        }
        public bool VerifyHash(byte[] hashToVerify, string usedHashOID, byte[] signedHash)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).VerifyHash(hashToVerify, usedHashOID, signedHash);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).VerifyHash(hashToVerify, signedHash);
            }
            throw new NotSupportedException("no hash verification logic for type " + typeof(T));
        }

        /// <summary>
        /// Verifies a previously signed hash to check the integrity
        /// of it.
        /// </summary>
        /// <typeparam name="U">The hash algorithm to use.</typeparam>
        /// <param name="dataToVerify">The hash of the message to verify.</param>
        /// <param name="signedHash">The previously signed hash of the message.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public override bool ComputeAndVerifyHash<U>(byte[] dataToVerify, byte[] signedHash)
        {
            return VerifyHash(new U().ComputeHash(dataToVerify), OIDIdentifier.Get(new U()), signedHash);
        }
    }
}
