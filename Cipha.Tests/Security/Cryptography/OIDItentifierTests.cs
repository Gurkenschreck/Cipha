using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography
{
    [TestClass]
    public class OIDIdentifierTests
    {
        [TestMethod]
        public void Get_PassHashAlg_Pass()
        {
            string expectedOID = "SHA1";
            string gotOID = OIDIdentifier.Get(HashAlg.SHA1);

            Assert.AreEqual(expectedOID, gotOID);
        }
        [TestMethod]
        public void Get_PassEncryptionAlg_Pass()
        {
            string expectedOID = "GOST3410";
            string gotOID = OIDIdentifier.Get(EncryptionAlg.GOST3410);

            Assert.AreEqual(expectedOID, gotOID);
        }
    }
}
