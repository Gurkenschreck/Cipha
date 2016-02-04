using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Asymmetric;
using System.Security.Cryptography;
using System.Text;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class ECDsaCipherTests
    {
        [TestMethod]
        public void SignHash_SignAndVerifyAHash_Pass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("wabdwadbwadbwadbw awdbwdbawd adbwdbw");
            byte[] hash;
            byte[] hash2;
            byte[] hash3;
            using(var x = new ECDsaCipher<ECDsaCng>())
            {
                hash = x.Algorithm.SignHash(dataToSign);
                hash2 = x.SignHash(dataToSign);
                hash3 = x.ComputeAndSignHash<SHA256Cng>(dataToSign);
            }
        }
    }
}
