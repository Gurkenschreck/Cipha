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

        /*public override void FromEncryptedXmlString<U>(string encryptedXmlString, string password, byte[] salt, int keySize = 0, int iterationCount = 10000)
        {
            using (var symAlgo = new SymmetricCipher<U>(password, (byte[])salt.Clone(), keySize, iterationCount))
            {
                FromXmlString(symAlgo.DecryptToString(encryptedXmlString), ECKeyXmlFormat.Rfc4050);
            }
        }*/

        public override byte[] SignData<U>(byte[] dataToSign)
        {
            if(algo is ECDsaCng)
            {
                return (algo as ECDsaCng).SignData(dataToSign);
            }
            throw new InvalidOperationException(string.Format("operation not supported by type {0}", typeof(T)));
        }

        public override bool VerifyData<U>(byte[] dataToVerify, byte[] signedData)
        {
            if(algo is ECDsaCng)
            {
                (algo as ECDsaCng).VerifyData(dataToVerify, signedData);
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
