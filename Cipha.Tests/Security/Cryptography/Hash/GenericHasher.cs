using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Hash;
using System.Security.Cryptography;
using System.Text;

namespace Cipha.Tests.Security.Cryptography.Hash
{
    [TestClass]
    public class GenericHasherTests
    {

        [TestMethod]
        public void SHA512BasicHash_GenerateHash_CompareOutput()
        {
            GenericHasher<SHA512Managed> hasher = new GenericHasher<SHA512Managed>();
            string stringToHash;
            string hashed;

            stringToHash = "This is my cool hasher!";

            hashed = hasher.ComputeHashBase64(stringToHash);

            Assert.AreEqual("VWCtgRIln4ysDD8kVqdoRDtUazQlEzRJtGXLJFqE49CUwTFmPF+agJsqZl4R3Od77Hv9k5x5Ozl+z+XjGYLqnA==", hashed);
        }

        [TestMethod]
        public void MD5BasicHash_GenerateHexHash_CompareOutput()
        {
            GenericHasher<MD5CryptoServiceProvider> hasher = new GenericHasher<MD5CryptoServiceProvider>();
            string stringToHash = "This is my hashable stuff";
            string hash = hasher.ComputeHashToHex(stringToHash, false);

            Assert.AreEqual("C00A7084E0EA4355B50240EE9EFA8E2A", hash);
        }

        [TestMethod]
        public void MD5CompareHash_GenerateHash_EqualHashReturnsTrue()
        {
            GenericHasher<MD5CryptoServiceProvider> hasher = new GenericHasher<MD5CryptoServiceProvider>();
            string stringToHash = "This is my hashable stuff";
            byte[] hash = hasher.ComputeHash(stringToHash);
            byte[] md5hash = new MD5CryptoServiceProvider().ComputeHash(hasher.Encoding.GetBytes(stringToHash));

            Assert.IsTrue(hasher.CompareHashes(hash, md5hash));
        }

        [TestMethod]
        public void SHA256BasicHash_GenerateHash_EqualsTrueReturnsSameOutput()
        {
            GenericHasher<SHA256Managed> hasher = new GenericHasher<SHA256Managed>();
            hasher.Encoding = Encoding.UTF8;
            string stringA = "welcoMe";
            string stringB = "welcoMe";

            Assert.IsTrue(hasher.CompareHashes(stringA, stringB));
        }
    }
}
