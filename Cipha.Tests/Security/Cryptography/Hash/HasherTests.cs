using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Cipha.Tests.Security.Cryptography.Hash
{
    [TestClass]
    public class HasherTests
    {
        [TestMethod]
        public void Instantiate_InstantiateAndDontDispose_Pass()
        {
            SHA1Cng refAlgo = new SHA1Cng();
            using(var digester = new Hasher<SHA1Cng>(refAlgo, false))
            { }
            Assert.IsNotNull(refAlgo);
        }
        [TestMethod]
        public void Hash_CompareHasheStringrAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            byte[] nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message);
                nativeHash = new SHA1Cng()
                    .ComputeHash(digester.Encoding.GetBytes(message));
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void Hash_CompareHasherBytesAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            byte[] digesterHash;
            byte[] nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(messageData);
                nativeHash = new SHA1Cng().ComputeHash(messageData);
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void Hash_CompareHasherStreamAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            byte[] digesterHash;
            byte[] nativeHash;
            using (MemoryStream ms = new MemoryStream())
            {
                using(StreamWriter sw = new StreamWriter(ms))
                {
                    sw.Write(messageData);

                    using (var digester = new Hasher<SHA1Cng>())
                    {
                        digesterHash = digester.Hash(ms);
                        nativeHash = new SHA1Cng().ComputeHash(ms);
                    }
                }
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void HashToString_CompareHasherBytesAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            string digesterHash;
            string nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.HashToString(messageData);
                nativeHash = Convert.ToBase64String(new SHA1Cng()
                    .ComputeHash(messageData));
            }
            Assert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void HashToString_CompareHasherStringAndNativeOutput_Pass()
        {
            string message = "Hash me";
            string digesterHash;
            string nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.HashToString(message);
                nativeHash = Convert.ToBase64String(new SHA1Cng()
                    .ComputeHash(digester.Encoding.GetBytes(message)));
            }
            Assert.AreEqual(nativeHash, digesterHash);
        }
    }
}
