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
            byte[] signedhash;
            bool verified = false;
            using(var x = new ECDsaCipher<ECDsaCng>())
            {
                hash = new SHA512Managed().ComputeHash(dataToSign);
                signedhash = x.SignHash(hash);
                verified = x.VerifyHash(hash, signedhash);
            }

            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void ComputeAndSignHash_ComputeAndSignHashAndVerifyAHash_Pass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("wabdwadbwadbwadbw awdbwdbawd adbwdbw");
            byte[] hash;
            byte[] signedhash;
            bool verified = false;

            using (var x = new ECDsaCipher<ECDsaCng>())
            {
                signedhash = x.ComputeAndSignHash<SHA1Managed>(dataToSign);
                hash = new SHA1Managed().ComputeHash(dataToSign);
                verified = x.VerifyHash(hash, signedhash);
            }

            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void ComputeAndSignHash_ComputeAndSignHashAndComputeAndVerifyHash_Pass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("wabdwadbwadbwadbw awdbwdbawd adbwdbw");
            byte[] signedhash;
            bool verified = false;

            using (var x = new ECDsaCipher<ECDsaCng>())
            {
                signedhash = x.ComputeAndSignHash<SHA1Managed>(dataToSign);
                verified = x.ComputeAndVerifyHash<SHA1Managed>(dataToSign, signedhash);
            }

            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void ComputeAndSignHash_SignHashAndComputeAndVerifyAHash_Pass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("wabdwadbwadbwadbw awdbwdbawd adbwdbw");
            byte[] hash;
            byte[] signedhash;
            bool verified = false;

            using (var x = new ECDsaCipher<ECDsaCng>())
            {
                hash = new SHA1Managed().ComputeHash(dataToSign);
                signedhash = x.SignHash(hash);
                verified = x.ComputeAndVerifyHash<SHA1Managed>(dataToSign, signedhash);
            }

            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void ComputeAndSignHash_SignHashAndComputeAndVerifyAHash_FalseDueToIncorrectHash()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("wabdwadbwadbwadbw awdbwdbawd adbwdbw");
            byte[] hash;
            byte[] signedhash;
            bool verified = false;

            using (var x = new ECDsaCipher<ECDsaCng>())
            {
                hash = new SHA1Managed().ComputeHash(dataToSign);
                signedhash = x.SignHash(hash);
                verified = x.ComputeAndVerifyHash<SHA512Managed>(hash, signedhash);
            }

            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void SignStringToString_SignHashAndComputeAndVerifyAHash_Pass()
        {
            string dataToSign = "wabdwadbwadbwadbw awdbwdbawd adbwdbw";
            string hash;
            bool verified = false;

            using (var x = new ECDsaCipher<ECDsaCng>())
            {
                hash = x.SignStringToString<SHA1Cng>(dataToSign);
                verified = x.VerifyString<SHA1Cng>(dataToSign, hash);
            }

            Assert.IsTrue(verified);
        }
    }
}
