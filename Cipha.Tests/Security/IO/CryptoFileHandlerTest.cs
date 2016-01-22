using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography.Symmetric;
using System.Security.Cryptography;
using Cipha.Security.IO;
using Cipha.Security.Cryptography;

namespace Cipha.Tests.Security.IO
{
    [TestClass]
    public class CryptoFileHandlerTest
    {
        [TestMethod]
        public void Constructor_PassReference_Pass()
        {
            string passwd = "superpassword";
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };

            Cipher originCipher;
            Cipher handlerCipher;

            using(SymmetricCipher<AesManaged> cipher = new SymmetricCipher<AesManaged>(passwd, salt))
            {
                using(var handler = new CryptoFileHandler<AesManaged>(cipher))
                {
                    handlerCipher = handler.Cipher;
                }
                originCipher = cipher;

                Assert.ReferenceEquals(originCipher, handlerCipher);
            }
        }

    }
}
