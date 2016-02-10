using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    [Serializable]
    public class ECDiffieHellmanAgreement
    {
        ECDiffieHellmanKeyDerivationFunction keyDerivationFunction;
        CngAlgorithm algorithm;
        CngKeyBlobFormat keyBlobFormat;

        public ECDiffieHellmanKeyDerivationFunction Function
        {
            get { return keyDerivationFunction; }
            set { keyDerivationFunction = value; }
        }

        public CngAlgorithm Algorithm
        {
            get { return algorithm; }
            set { algorithm = value; }
        }

        public CngKeyBlobFormat BlobFormat
        {
            get { return keyBlobFormat; }
            set { keyBlobFormat = value; }
        }

        public ECDiffieHellmanAgreement() 
            : this(ECDiffieHellmanKeyDerivationFunction.Hash, CngAlgorithm.Sha256, CngKeyBlobFormat.EccPublicBlob)
        {

        }
        public ECDiffieHellmanAgreement(ECDiffieHellmanKeyDerivationFunction function, CngAlgorithm algorithm, CngKeyBlobFormat format)
        {
            this.keyDerivationFunction = function;
            this.algorithm = algorithm;
            this.keyBlobFormat = format;
        }

        public byte[] ToBytes()
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using(var ms = new MemoryStream())
            {
                formatter.Serialize(ms, this);
                return ms.ToArray();
            }
        }
    }
}
