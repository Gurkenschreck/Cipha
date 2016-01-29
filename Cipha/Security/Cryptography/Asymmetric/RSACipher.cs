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
        /// Gets or sets the current used key size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                return algo.KeySize;
            }
            set
            {
                if (algo is RSACryptoServiceProvider)
                {
                    using (RSACryptoServiceProvider crypto = new RSACryptoServiceProvider(value))
                    {
                        algo.FromXmlString(crypto.ToXmlString(true));
                    }
                }
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


        public override byte[] SignData<U>(byte[] dataToSign)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).SignData(dataToSign, new U());
            }
            throw new NotSupportedException("no data signing logic for type " + typeof(T));
        }

        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).VerifyData(dataToVerify, new U(), signedData);
            }
            throw new NotSupportedException("no verifying logic for type " + typeof(T));
        }

        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData, string xmlString)
        {
            if (algo is RSACryptoServiceProvider)
            {
                using(var tempAlgo = new RSACryptoServiceProvider())
                {
                    tempAlgo.FromXmlString(xmlString);
                    return tempAlgo.VerifyData(dataToVerify, new U(), signedData);
                }
            }
            throw new NotSupportedException("no verifying logic for type " + typeof(T));
        }

        public override byte[] SignHash(byte[] hashToSign, string hashIdentifier)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).SignHash(hashToSign, hashIdentifier);
            }
            throw new NotSupportedException("no hash signing logic for type " + typeof(T));
        }

        public override bool VerifyHash(byte[] hashToVerify, string hashIdentifier, byte[] signedHash)
        {
            if (algo is RSACryptoServiceProvider)
            {
                return (algo as RSACryptoServiceProvider).VerifyHash(hashToVerify, hashIdentifier, signedHash);
            }           
            throw new NotSupportedException("no hash verifying logic for type " + typeof(T));
        }

        public override bool VerifyHash(byte[] hashToVerify, string hashIdentifier, byte[] signedHash, string xmlString)
        {
            if (algo is RSACryptoServiceProvider)
            {
                using(var tempAlgo = new RSACryptoServiceProvider())
                {
                    tempAlgo.FromXmlString(xmlString);
                    return tempAlgo.VerifyHash(hashToVerify, hashIdentifier, signedHash);
                }
            }
            throw new NotSupportedException("no hash verifying logic for type " + typeof(T));
        }
    }
}
