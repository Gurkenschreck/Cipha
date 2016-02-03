using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipha.Security.Cryptography.Asymmetric;
using System.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class DSACipherTest
    {
        [TestMethod]
        public void SignData_SignAndVerifyMessage_Pass()
        {
            Random rdm = new Random();
            byte[] randomMessage = new byte[128];
            rdm.NextBytes(randomMessage);
            byte[] hashSignature;
            bool notTamperedWith = false;

            using(var cipher = new DSACipher<DSACryptoServiceProvider>())
            {
                hashSignature = cipher.SignHash<SHA512Cng>(randomMessage);

                notTamperedWith = cipher.VerifyHash<SHA512Cng>(randomMessage, hashSignature);
            }

            Assert.IsTrue(notTamperedWith);
        }
    }
}
