using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using Cipha.Security.Cryptography.Hash;

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
        public void Instantiate_InstantiateAndDispose_Pass()
        {
            SHA1Cng refAlgo = new SHA1Cng();
            using (var digester = new Hasher<SHA1Cng>(refAlgo, true))
            { }
            Assert.IsNotNull(refAlgo);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void Hash_PassNullBytes_FailNullException()
        {
            byte[] message = null;
            byte[] digesterHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message);
            }
        }
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        [TestMethod]
        public void Hash_PassZeroIterations_FailOutOfRangeException()
        {
            byte[] message = { 4, 2, 3 };
            byte[] digesterHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message, 0);
            }
        }
        [TestMethod]
        public void LastHash_GetHashOfLastComputation_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            byte[] lastHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(digester.Encoding.GetBytes(message));
                lastHash = digester.LastHash;
            }
            CollectionAssert.AreEqual(lastHash, digesterHash);
        }
        [TestMethod]
        public void LastHash_ComputeTwoHashAndCompare_PassNotEqual()
        {
            string message = "Hash me";
            string message2 = "Other string and message bueno";
            byte[] digesterHash;
            byte[] firstHash;
            byte[] lastHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(digester.Encoding.GetBytes(message));
                firstHash = digester.LastHash;
                digester.Hash(digester.Encoding.GetBytes(message2));
                lastHash = digester.LastHash;
            }
            CollectionAssert.AreNotEqual(firstHash, lastHash);
        }
        [TestMethod]
        public void Hash_CompareHashRangeStringAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            byte[] nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(digester.Encoding.GetBytes(message), 3, 4);

                Encoding enc = digester.Encoding;
                nativeHash = new SHA1Cng().ComputeHash(enc.GetBytes(message), 3, 4);
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void HashRounds_CompareHashStringAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            byte[] nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message, 3);

                Encoding enc = digester.Encoding;
                nativeHash = new SHA1Cng().ComputeHash(enc.GetBytes(message));
                nativeHash = new SHA1Cng().ComputeHash(nativeHash);
                nativeHash = new SHA1Cng().ComputeHash(nativeHash);
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void Hash_CompareHashRoundsStringAndNativeOutput_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            byte[] nativeHash;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message, 3);

                Encoding enc = digester.Encoding;
                nativeHash = new SHA1Cng().ComputeHash(enc.GetBytes(message));
                nativeHash = new SHA1Cng().ComputeHash(nativeHash);
                nativeHash = new SHA1Cng().ComputeHash(nativeHash);
            }
            CollectionAssert.AreEqual(nativeHash, digesterHash);
        }
        [TestMethod]
        public void Hash_CompareHashStringAndNativeOutput_Pass()
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
        [TestMethod]
        public void VerifyHash_ValidateStringAndByteHash_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            bool same = false;
            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message);
                same = digester.VerifyHash(message, digesterHash);
            }
            Assert.IsTrue(same);
        }
        [TestMethod]
        public void VerifyHash_ComputeToStringValidateStringAndByteHash_Pass()
        {
            string message = "Hash me";
            string digesterHash;
            bool same = false;

            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.HashToString(message);
                same = digester.VerifyHash(message, digesterHash);
            }
            Assert.IsTrue(same);
        }
        [TestMethod]
        public void VerifyHash_ValidateBytesAndByteHash_Pass()
        {
            string message = "Hash me";
            byte[] digesterHash;
            bool same = false;

            using (var digester = new Hasher<SHA1Cng>())
            {
                digesterHash = digester.Hash(message);
                same = digester.VerifyHash(digester.Encoding.GetBytes(message), digesterHash);
            }
            Assert.IsTrue(same);
        }
    }
}
