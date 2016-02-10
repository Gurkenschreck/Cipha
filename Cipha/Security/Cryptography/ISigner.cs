using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public interface ISigner
    {
        abstract byte[] SignHash(byte[] hash);
        abstract bool VerifyHash(byte[] validationHashbyte, byte[] hashSignature);
        abstract byte[] SignData(byte[] dataToSign);
        abstract bool VerifyData(byte[] dataToVerify, byte[] dataSignature);

    }
}
