using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
{
    /// <summary>
    /// Digital Signature Algorithm is used to create
    /// digital signatures of data for verificational
    /// reasons.
    /// 
    /// Using digital signatures, one can verify the
    /// identity of a message and if the message itself
    /// has been manipulated.
    /// 
    /// DSA uses SHA1 for the creation of
    /// digital signatures.
    /// 
    /// DSA supports key lengths from 512 bits to 1024 
    /// bits in increments of 64 bits.
    /// 
    /// There are newer asymmetric algorithms, so consider
    /// leaving using RSA, ECDsa or ECDiffieHellmann.
    /// </summary>
    /// <typeparam name="T">The DSA implementation.</typeparam>
    public class DSACipher<T> : AsymmetricCipher<T>
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
            if(algo is DSACryptoServiceProvider)
            {
                return (algo as DSACryptoServiceProvider).SignData(dataToSign);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).SignData(dataToSign);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));
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
            if (algo is DSACryptoServiceProvider)
            {
                return (algo as DSACryptoServiceProvider).VerifyData(dataToVerify, signedData);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).VerifyData(dataToVerify, signedData);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));
        }

        /// <summary>
        /// Creates a signature for the specified pre-calculated 
        /// hash value.
        /// 
        /// Some hash identifier can be found in the
        /// OIDIdentifier class.
        /// </summary>
        /// <param name="dataToSign">The hash to sign.</param>
        /// <returns>The signature of the hash.</returns>
        public override byte[] SignHash(byte[] hashToSign)
        {
            return algo.CreateSignature(new SHA1Cng().ComputeHash(hashToSign));
        }

        /// <summary>
        /// Verifies a previously signed hash to check the integrity
        /// of it.
        /// </summary>
        /// <param name="dataToVerify">The hash of the message to verify.</param>
        /// <param name="signedHash">The previously signed hash of the message.</param>
        /// <returns>If the message has not been tampered with.</returns>
        public override bool VerifyHash(byte[] hashToVerify, byte[] signedHash)
        {
            return algo.VerifySignature(new SHA1Cng().ComputeHash(hashToVerify), signedHash);
        }
    }
}
