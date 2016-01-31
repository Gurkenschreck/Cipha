using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
{
    public class DRACipher<T> : AsymmetricCipher<T>
        where T : DSA, new()
    {
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
        public override byte[] SignData<U>(byte[] dataToSign)
        {
            byte[] hash = new U().ComputeHash(dataToSign);
            return (algo as DSACryptoServiceProvider).CreateSignature(hash);
        }

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
        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            byte[] hash = new U().ComputeHash(dataToVerify);
            return algo.VerifySignature(hash, signedData);
        }

        /// <summary>
        /// Creates a signature for the specified pre-calculated 
        /// hash value.
        /// 
        /// Some hash identifier can be found in the
        /// OIDIdentifier class.
        /// </summary>
        /// <param name="hashToSign">The hash to sign.</param>
        /// <returns>The signature of the hash.</returns>
        public override byte[] SignHash<U>(byte[] hashToSign)
        {
            byte[] hash = new U().ComputeHash(hashToSign);
            return algo.CreateSignature(hashToSign);
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
            byte[] hash = new U().ComputeHash(hashToVerify);
            return algo.VerifySignature(hash, signedHash);
        }        
    }
}
