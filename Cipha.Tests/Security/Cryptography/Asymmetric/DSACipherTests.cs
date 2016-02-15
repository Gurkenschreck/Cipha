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
        public void ComputeAndSignHash_SignAndVerifyMessage_Pass()
        {
            Random rdm = new Random();
            byte[] randomMessage = new byte[128];
            rdm.NextBytes(randomMessage);
            byte[] hashSignature;
            bool notTamperedWith = false;

            using(var cipher = new DSACipher<DSACryptoServiceProvider>())
            {
                hashSignature = cipher.ComputeAndSignHash<SHA512Cng>(randomMessage);

                notTamperedWith = cipher.ComputeAndVerifyHash<SHA512Cng>(randomMessage, hashSignature);
            }

            Assert.IsTrue(notTamperedWith);
        }
        [TestMethod]
        public void Intitialize_PassReferenceInConstructor_Pass()
        {
            Random rdm = new Random();
            byte[] randomMessage = new byte[128];
            byte[] randomMessageHash;
            rdm.NextBytes(randomMessage);
            byte[] hashSignature;
            bool notTamperedWith = false;

            using (var csp = new DSACryptoServiceProvider())
            {
                randomMessageHash = new SHA1Managed().ComputeHash(new SHA512Cng().ComputeHash(randomMessage));
                hashSignature = csp.CreateSignature(randomMessageHash);

                using(var cipher = new DSACipher<DSACryptoServiceProvider>(csp))
                {
                    notTamperedWith = cipher.ComputeAndVerifyHash<SHA512Cng>(randomMessage, hashSignature);
                }
            }

            Assert.IsTrue(notTamperedWith);
        }
    }
}
