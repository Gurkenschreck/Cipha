using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using Cipha.Security.Cryptography;
using Cipha.Security.Cryptography.Symmetric;
using Cipha.Security.Cryptography.Asymmetric;

namespace Cipha.Tests.Security.Cryptography.Asymmetric
{
    [TestClass]
    public class ECDiffieHellmanCipherTests
    {
        [TestMethod]
        public void DeriveKey_CreateCommonKeyAndEncryptString_Pass()
        {
            ECDiffieHellmanAgreement agreement;
            byte[] commonKey;
            byte[] iv;
            string messageFromBob = "Hello my friend, how are you?";
            string encrypted;
            string decrypted;

            using(var alice = new ECDiffieHellmanCipher<ECDiffieHellmanCng>())
            {
                agreement = alice.Agreement;
                using(var bob = new ECDiffieHellmanCipher<ECDiffieHellmanCng>(agreement))
                {
                    commonKey = alice.DeriveKey(bob.PublicKey);
                    using (var cipher = new SymmetricCipher<AesManaged>(commonKey, out iv))
                        encrypted = cipher.EncryptToString(messageFromBob);
                }

                using (var cipher = new SymmetricCipher<AesManaged>(commonKey, iv))
                    decrypted = cipher.DecryptToString(encrypted);
            }

            Assert.AreEqual(messageFromBob, decrypted);
        }

        [TestMethod]
        public void DeriveKey_CompareCommonKey_Pass()
        {
            ECDiffieHellmanAgreement agreement;
            byte[] aliceKey;
            byte[] bobKey;

            using (var alice = new ECDiffieHellmanCipher<ECDiffieHellmanCng>())
            {
                agreement = alice.Agreement;
                using (var bob = new ECDiffieHellmanCipher<ECDiffieHellmanCng>(agreement))
                {
                    aliceKey = alice.DeriveKey(bob.PublicKey);
                    bobKey = bob.DeriveKey(alice.PublicKey);
                }
            }

            CollectionAssert.AreEqual(aliceKey, bobKey);
        }
    }
}
