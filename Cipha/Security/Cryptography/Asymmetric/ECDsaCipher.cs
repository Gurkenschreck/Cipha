using Cipha.Security.Cryptography.Symmetric;
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
        public ECDsaCipher(int keySize = 0) : base(keySize) { }
        public ECDsaCipher(T algo, bool disposeAlgorithm = false) : base(algo, disposeAlgorithm) { }
        public ECDsaCipher(string cleartextXmlString) : base(cleartextXmlString) { }
        public ECDsaCipher(string encryptedXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int iterationCount = 10000)
            : base(encryptedXmlString, password, salt, IV, keySize, iterationCount) { }
        public override void FromXmlString(string xmlString)
        {
            FromXmlString(xmlString, ECKeyXmlFormat.Rfc4050);
        }
        public void FromXmlString(string xmlString, ECKeyXmlFormat format)
        {
            if(algo is ECDsaCng)
            {
                (algo as ECDsaCng).FromXmlString(xmlString, format);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));
        }
        
        public override byte[] SignData<U>(byte[] dataToSign)
        {
            if(algo is ECDsaCng)
            {
                return (algo as ECDsaCng).SignData(dataToSign);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).SignData(dataToSign);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));
        }

        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            if(algo is ECDsaCng)
            {
                return (algo as ECDsaCng).VerifyData(dataToVerify, signedData);
            }
            if(algo is ISigner)
            {
                return (algo as ISigner).VerifyData(dataToVerify, signedData);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));

        }

        public override byte[] SignHash(byte[] hashToSign)
        {
            return algo.SignHash(hashToSign);
        }

        public override bool VerifyHash(byte[] hashToVerify, byte[] signedHash)
        {
            return algo.VerifyHash(hashToVerify, signedHash);
        }
    }
}
