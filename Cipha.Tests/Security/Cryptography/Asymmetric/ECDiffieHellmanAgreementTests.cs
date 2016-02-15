using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Asymmetric;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class ECDiffieHellmanAgreementTests
    {
        [TestMethod]
        public void ToBytes_ConvertAgreementToBytes_Pass()
        {
            ECDiffieHellmanAgreement agreement = new ECDiffieHellmanAgreement();
            byte[] agreementBytes = agreement.ToBytes();
            byte[] agreementNativeBytes;

            BinaryFormatter formatter = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                formatter.Serialize(ms, agreement);
                agreementNativeBytes = ms.ToArray();
            }
            
            CollectionAssert.AreEqual(agreementBytes, agreementNativeBytes);
        }

        [TestMethod]
        public void FromBytes_ConvertBytesToAgreement_Pass()
        {
            ECDiffieHellmanAgreement agreement = new ECDiffieHellmanAgreement();
            byte[] agreementBytes = agreement.ToBytes();

            // Send bytes over network

            ECDiffieHellmanAgreement remoteAgreement = ECDiffieHellmanAgreement.FromBytes(agreementBytes);


            Assert.IsNotNull(remoteAgreement);
        }

        [TestMethod]
        public void EqualOperator_CompareWithOverloadedEqual_Pass()
        {
            ECDiffieHellmanAgreement agreement = new ECDiffieHellmanAgreement();
            ECDiffieHellmanAgreement agreement2 = new ECDiffieHellmanAgreement();


            Assert.IsTrue(agreement == agreement2);
        }
        [TestMethod]
        public void InEqualOperator_CompareWithOverloadedInEqual_Pass()
        {
            ECDiffieHellmanAgreement agreement = new ECDiffieHellmanAgreement();
            ECDiffieHellmanAgreement agreement2 = new ECDiffieHellmanAgreement();
            agreement.Function = ECDiffieHellmanKeyDerivationFunction.Tls;

            Assert.IsTrue(agreement != agreement2);
        }
    }
}
