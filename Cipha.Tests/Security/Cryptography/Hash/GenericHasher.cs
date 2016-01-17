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
        public void StringSHA512Hash()
        {
            GenericHasher<SHA512Managed> hasher = new GenericHasher<SHA512Managed>();

            string stringToHash = "This is my cool hasher!";
            byte[] stringToHashBytes;
            byte[] hashed;
            string base64Hash;

            stringToHashBytes = hasher.Encoding.GetBytes(stringToHash);

            hashed = hasher.ComputeHash(stringToHashBytes);

            base64Hash = Convert.ToBase64String(hashed);
            Assert.AreEqual("VWCtgRIln4ysDD8kVqdoRDtUazQlEzRJtGXLJFqE49CUwTFmPF+agJsqZl4R3Od77Hv9k5x5Ozl+z+XjGYLqnA==", base64Hash);
        }

        [TestMethod]
        public void ComputeHashBase64Test()
        {
            GenericHasher<SHA512Managed> hasher = new GenericHasher<SHA512Managed>();
            string stringToHash;
            string hashed;

            stringToHash = "This is my cool hasher!";

            hashed = hasher.ComputeHashBase64(stringToHash);

            Assert.AreEqual("VWCtgRIln4ysDD8kVqdoRDtUazQlEzRJtGXLJFqE49CUwTFmPF+agJsqZl4R3Od77Hv9k5x5Ozl+z+XjGYLqnA==", hashed);
        }

        [TestMethod]
        public void ComputeMD5Hash()
        {
            GenericHasher<MD5CryptoServiceProvider> hasher = new GenericHasher<MD5CryptoServiceProvider>();
            string stringToHash = "This is my hashable stuff";
            string hash = hasher.ComputeHashToHex(stringToHash, false);

            Assert.AreEqual("C00A7084E0EA4355B50240EE9EFA8E2A", hash);
        }

        [TestMethod]
        public void ComputeMD5HashAndCompareToOriginalImplementation()
        {
            GenericHasher<MD5CryptoServiceProvider> hasher = new GenericHasher<MD5CryptoServiceProvider>();
            string stringToHash = "This is my hashable stuff";
            byte[] hash = hasher.ComputeHash(stringToHash);
            byte[] md5hash = new MD5CryptoServiceProvider().ComputeHash(hasher.Encoding.GetBytes(stringToHash));

            Assert.IsTrue(hasher.CompareHashes(hash, md5hash));
        }

        [TestMethod]
        public void CompareSHA512HashString()
        {
            GenericHasher<SHA512Managed> hasher = new GenericHasher<SHA512Managed>();
            hasher.Encoding = Encoding.UTF8;
            string stringA = "welcoMe";
            string stringB = "welcoMe";

            Assert.IsTrue(hasher.CompareHashes(stringA, stringB));
        }
    }
}
