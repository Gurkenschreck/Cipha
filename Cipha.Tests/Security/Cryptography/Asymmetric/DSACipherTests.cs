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

            using(var cipher = new DSACipher<DSACryptoServiceProvider>())
            {
            }
        }
    }
}
