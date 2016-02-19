using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using Cipha.Security.Cryptography.Hash;
using System.Text;
using Cipha.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography.Hash
{
    [TestClass]
    public class HMACerTests
    {
        [TestMethod]
        public void Instantiate_TripleDESEmptyConstructor_Pass()
        {
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>();
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();

            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [TestMethod]
        public void Instantiate_StringKeyConstructor_Pass()
        {
            string keyString = "hmacerfun i like it :)";
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<HMACSHA512> hmacer = new HMACer<HMACSHA512>(keyString);
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();

            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [TestMethod]
        public void Instantiate_StringKeyConstructorToTripleDES_Pass()
        {
            string keyString = "$2ba.ä#,:;425?=)424dphu";
            byte[] b = Encoding.UTF8.GetBytes(keyString);
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>(keyString);
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();
            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [ExpectedException(typeof(CryptographicException))]
        [TestMethod]
        public void Instantiate_StringKeyConstructorToTripleDESBadKey_FailCryptoException()
        {
            string keyString = "hmacerfun i like it :)";
            byte[] b = Encoding.UTF8.GetBytes(keyString);
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>(keyString);
            hmacer.Dispose();
            Assert.Fail("should have failed with crypto exception because of invalid plainData size");
        }
        [TestMethod]
        public void Instantiate_TripleDESKeyPass_Pass()
        {
            var descsp = new TripleDESCryptoServiceProvider();
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>(descsp.Key);
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();
            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void Instantiate_PassNullArgumentReference_FailNullArgument()
        {
            TripleDESCryptoServiceProvider descsp = null;
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>(descsp);
            hmacer.Dispose();
            Assert.Fail("Should have failed with null argument exception");
        }
        [TestMethod]
        public void Instantiate_TripleDESKeylengtPass_Pass()
        {
            int keylength = 16;
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<MACTripleDES> hmacer = new HMACer<MACTripleDES>(keylength);
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();
            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [TestMethod]
        public void Instantiate_AesReferencePassed_Pass()
        {
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            using (var descsp = new AesManaged())
            {
                HMACer<HMACSHA256> hmacer = new HMACer<HMACSHA256>(descsp);
                hmacOfMessage = hmacer.HashToString(message);
                secondHmacOfMessage = hmacer.HashToString(message);
                hmacer.Dispose();
            }
            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [TestMethod]
        public void Instantiate_PassWantedKeyLength_Pass()
        {
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            string secondHmacOfMessage;
            HMACer<HMACSHA256> hmacer = new HMACer<HMACSHA256>(42);
            hmacOfMessage = hmacer.HashToString(message);
            secondHmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();
            
            Assert.AreEqual(hmacOfMessage, secondHmacOfMessage);
        }
        [TestMethod]
        public void VerifyHash_VerifyHashWithSecondInstance_Pass()
        {
            string message = "Fun fun fun the ocean is blue ,_:;=$";
            string hmacOfMessage;
            byte[] key = Encoding.UTF8.GetBytes(message);
            byte[] copy;
            bool isMessageOriginal = false;

            HMACer<HMACSHA256> hmacer = new HMACer<HMACSHA256>(key);
            copy = hmacer.Key;
            hmacOfMessage = hmacer.HashToString(message);
            hmacer.Dispose();

            using(var hmcr = new HMACer<HMACSHA256>(copy))
            {
                isMessageOriginal = hmcr.VerifyHash(message, hmacOfMessage);
            }

            Assert.IsTrue(isMessageOriginal);
        }
    }
}
