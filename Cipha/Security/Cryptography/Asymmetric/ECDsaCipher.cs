using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
{
    public class ECDsaCipher<T> : AsymmetricCipher<T>
        where T : ECDsa, new()
    {
        public override byte[] SignData<U>(byte[] dataToSign)
        {
            throw new NotImplementedException();
        }

        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            throw new NotImplementedException();
        }

        public override byte[] SignHash<U>(byte[] hashToSign)
        {
            throw new NotImplementedException();
        }

        public override bool VerifyHash<U>(byte[] hashToVerify, byte[] signedHash)
        {
            throw new NotImplementedException();
        }
    }
}
