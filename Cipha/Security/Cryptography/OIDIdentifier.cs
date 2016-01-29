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
