using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public static class OIDIdentifier
    {
        public static string Get(HashAlg algo)
        {
            return Enum.GetName(typeof(HashAlg), algo);
        }
        public static string Get(EncryptionAlg algo)
        {
            return Enum.GetName(typeof(EncryptionAlg), algo);
        }
        public static string Get(HashAlgorithm algo)
        {
            if (algo is SHA1)
                return "SHA1";
            if (algo is SHA256)
                return "SHA256";
            if (algo is SHA384)
                return "SHA384";
            if (algo is SHA512)
                return "SHA512";
            if (algo is MD5)
                return "MD5";
            if (algo is RIPEMD160)
                return "RIPEMD160";

            throw new UnknownAlgorithmException("uncatched algorithm " + algo.GetType());
        }

        /// <summary>
        /// Creates a new crypto service provider instance of algo.
        /// 
        /// Exception: RIPEMD160, that is managed.
        /// </summary>
        /// <param name="algo">The algorithm to create an equivalent instance of.</param>
        /// <returns>The new instance.</returns>
        public static HashAlgorithm GetInstance(HashAlg algo)
        {
            switch(algo)
            {
                case HashAlg.SHA1:
                    return new SHA1CryptoServiceProvider();
                case HashAlg.SHA256:
                    return new SHA256CryptoServiceProvider();
                case HashAlg.SHA384:
                    return new SHA384CryptoServiceProvider();
                case HashAlg.SHA512:
                    return new SHA512CryptoServiceProvider();
                case HashAlg.MD5:
                    return new MD5CryptoServiceProvider();
                case HashAlg.RIPEMD160:
                    return new RIPEMD160Managed();
                default:
                    throw new UnknownAlgorithmException("uncatched algorithm " + algo);
            }
        }
    }
    public enum HashAlg
    {
        MD5,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        RIPEMD128,
        RIPEMD160,
        RIPEMD256,
        GOST3411
    }
    public enum EncryptionAlg
    {
        DSA,
        RSA,
        ECDSA,
        RSAandMGF1,
        GOST3410,
        ECGOST3410
    }
}
