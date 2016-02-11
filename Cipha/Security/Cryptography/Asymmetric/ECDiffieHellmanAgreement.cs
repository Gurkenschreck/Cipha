using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Asymmetric
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
        public static ECDiffieHellmanAgreement FromBytes(byte[] agreementBytes)
        {
            using (var memStream = new MemoryStream())
            {
                var binForm = new BinaryFormatter();
                memStream.Write(agreementBytes, 0, agreementBytes.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                return binForm.Deserialize(memStream) as ECDiffieHellmanAgreement;
            }
        }

        // Operator overloading
        public static bool operator ==(ECDiffieHellmanAgreement agr1, ECDiffieHellmanAgreement agr2)
        {
            bool isEqual = false;

            if (agr1.Algorithm.Algorithm != agr2.Algorithm.Algorithm)
                return isEqual;

            if (agr1.BlobFormat.Format != agr2.BlobFormat.Format)
                return isEqual;

            if (agr1.Function != agr2.Function)
                return isEqual;

            return !isEqual;
        }
        public static bool operator !=(ECDiffieHellmanAgreement agr1, ECDiffieHellmanAgreement agr2)
        {
            bool isUnequal = true;
            if (agr1.Algorithm != agr2.Algorithm)
                return isUnequal;

            if (agr1.BlobFormat != agr2.BlobFormat)
                return isUnequal;

            if (agr1.Function != agr2.Function)
                return isUnequal;

            return !isUnequal;
        }

        public override bool Equals(object obj)
        {
            ECDiffieHellmanAgreement other = obj as ECDiffieHellmanAgreement;

            if(other != null)
            {
                return other == this;
            }
            return false;
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
