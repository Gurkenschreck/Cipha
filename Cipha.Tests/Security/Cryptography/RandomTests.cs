using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cipha.Tests.Security.Cryptography
{
    [TestClass]
    public class RandomTests
    {
        [TestMethod]
        public void FillWithRandomBytes_GenerateBytes_PassNotEqual()
        {
            byte[] bytes1 = new byte[20];
            byte[] bytes2 = new byte[20];

            Cipha.Security.Cryptography.Random rdm = new Cipha.Security.Cryptography.Random();
            rdm.FillWithRandomBytes(bytes1);
            rdm.FillWithRandomBytes(bytes2);

            Assert.AreNotEqual(bytes1, bytes2);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void FillWithRandomBytes_GenerateBytes_ArgumentNullExceptionFail()
        {
            byte[] bytes1 = null;

            Cipha.Security.Cryptography.Random rdm = new Cipha.Security.Cryptography.Random();
            rdm.FillWithRandomBytes(bytes1);
        }
    }
}
