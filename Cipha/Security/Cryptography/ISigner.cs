using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    /// <summary>
    /// Provides an interface to sign and verify
    /// data.
    /// 
    /// Compensates the lack of ability to sign
    /// and verify data.
    /// </summary>
    public interface ISigner
    {
        byte[] SignHash(byte[] hash);
        bool VerifyHash(byte[] validationHashbyte, byte[] hashSignature);
        byte[] SignData(byte[] dataToSign);
        bool VerifyData(byte[] dataToVerify, byte[] dataSignature);
    }
}
