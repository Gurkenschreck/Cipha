using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;
using System.Security.Cryptography;
using Cipha.Security.Cryptography.Symmetric;
using Cipha.Security.Cryptography.Asymmetric;
using System.Text;

namespace Cipha.Tests.Security.Cryptography
{
    [TestClass]
    public class KeyPackerTests
    {
        string rsaEncryptedXmlString = "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";
        string rsaPlainXmlString = "<RSAKeyValue><Modulus>557iP1As0J5JfLxCVgrGmufYjdB3SYi2bbtF8501A8U+iasOudzQYUXj2t8Yl3M1yVkgCccVX3Xxzmf9b1D0sZzrya+RMtEqhf5DkRsMI8zoWmoV5KFSfHW30x1MmNoJ5v2t50UlPFMect0JwxyLv3ggVAzfacHkOtslizVj1EaWORShj1227Usg+BfasMMnPEvr0KI9E/u5h0EmaymhE8uWaEW+b8n2B6TknQ1hKCfy286QC7DDEsgP/BtBYlKAXEiWrc1C8Ptzf5VXJf4WhiLid7X7qaDVPxaFGKYz67VKFLnT7+e+qHsGSQIHrvAZbDo9J9t5j78SExQEGTs+cQ==</Modulus><Exponent>AQAB</Exponent><P>79MOWxBLM5p1IZ3ICtxpNJkFx0nKEzs/fUd54j1H/vW9phQOGC6ZCApjhaUj3Y18hwwLN//ToLkYgX/hxGapjFwAYOE7yxpBL+kk9pGdpUgojs4sIsqnmYbn/iOQx+BZvYzOHfGIt7C+rE1FKrA1qNx9NFoF6GvEBbq51S5vPTc=</P><Q>9z4tIgY9U0skwzVFiLpqnLS9WfBzUNPs4WthxPdsSO5o98LTn4jmwWVWtEhvKEsWvyWwTewNwlAh5GFYxTZufGYfg9MzgSFRb4y7pq0dj21SmXRRk8GnxuG0rCBO1CnWGXt7IzVEa8cIzqEdmz/H4oqfesbHRbOwlZilioh8dZc=</Q><DP>P/dDNPa7mB/ybezvljYDuYu3BtiflVGQNZIC6Fz//vj8hHeE6t5C4uoicVsCne1G8Z48v8r0X0H/T0sUpJXdUxqW30Az+pAeIvFEcp+UNKlyZ+SF0SHMYh6hch96VlV4mh4cO9BYbuYtdTeG40PsjAWDP5tjSAK2XfDX8AxajzE=</DP><DQ>dViEUU7G0n6qvx/Mld1sdl3uNP7DrIw5NLAjojmQonjNRzKoAGMYqpevdDeg0m35KNX5fLJZwW0I+P0fBdMU02Qg9w9JtbMblKcl9TDbA9TuTDkB8vAJ8oHzn3JiF56XqFaMFiTVCZZY3sFnbOTzuNj0YnBv6ewkFoxxnXO0Jpc=</DQ><InverseQ>WXvaH3dh7J5PpWSNsI2D2BD34UEzBoE3S2TmIwGpaxwXxgKlqmvey8x+ry+E63DrJenhrNuytKyt+xOO8oo9QAq1O7Oex1iR9IfEFMY3FIlo/4hJDjPJcpg+bNVhjaoC0TOw3HRWrzfxUAXiblgn6OfJZaZGecfBRzTW/SYQnSs=</InverseQ><D>K4sGjJGFg0imlxELRYKsGJYKc4qjykqtxQ5GVciRnV5Y5eenEpDtCcRqVAzJ4jrx+yLKr5viLDqPlVaeYe1tuvA9sYJUgSGqZVtKF37mttpAOjMkX4FmcOhugP1Kl5ex8d9x8H7iw6b6m+xq9+ena/zo0vRCke61+cyWD8gfNtoctZiQTzkA2QlcPbhjaoBAfuHvd/uIgut6b2CPXE0OUbMpWafczYuAO6UNpoSRovHXzfdbWWSScOlVd80ULztRHcWVw8QC69LDvflgU5YSvrexfWzRLXRRSzrIRWT6S5bbbJTDO5RJZYvzYDt9UCjoQxTtzOzGiNsu3NZYavT6Uw==</D></RSAKeyValue>";
        string symConfigXmlString = "<SymmetricCipher><EncryptedKey>ZX3kIj4SjAx8VN/gzHS+hcS5/QIG6+LYWLsRVgVOBKmaihpI9hQazuTXLHDC/E4x9B2d9cKndIkfL+lVwRZg1lcKydY6XZrSHKwgplbwFj9yWNdDavivo/F4GiCFwDMupuu9VcJwrvQKeuVFSN+TRZKsg9NMkWjCo5xVhhCWAK9MgJfsCc8QmMGGq0Tyy3PCvgzULeCbbMZuEKma2FVMKc2eSoOahjfkef5olaCXcwZuJ/TM1/fW8/tBIGIV9BS7nUnvbt7YQIcFxfiu2b0o1ibkAHqVmWiaywagvISVBaa1NgT7mhFpbVCOYMZB01L9yl2mX2JBnmWqKaIiZQe6Wg==</EncryptedKey><IV>r9HYVciB47dHj63Um7jUXD4SsQRWptfuHNs9WZETVszrMxiNXccRlktotlC5vfCTw3QOYZsUpxIXhCfzh7zDKNqWcmzt2hUiT0qM3Wx2nAQqytlJ57gHicn02l1Qck1bewXG50Ixq4j9J1TdW0HRI1V0kHWL07SMLAMaCe+axsPVR2dM/pk2JhQQqY6QAdeRpqVoXTNRIuHsna0Kog9e/wPvkQi28muM/sx3SFg4lszRz9bmWZCliH/7Mms5B1TB0NFwpFZrEjhhArcmV0RG8K5OTOmgSom0SXIt5R75kQj48SlCY0nU9CZBDlHm8fr6O8zArlXJVqQVZMP0dfmkbg==</IV><BlockSize>128</BlockSize><Salt></Salt><Iterations>10000</Iterations><Encoding>System.Text.UTF8Encoding</Encoding></SymmetricCipher>";
        [TestMethod]
        public void Instantiate_PassEncryptedXmlString_Pass()
        {
            string encryptedPublicKeyXmlStringFromSomewhere = rsaEncryptedXmlString;
            byte[] salt = {
                              1,2,3,4,5,6,7,8,9
                          };
            byte[] IV = {
                            91, 154, 27, 116, 116, 160, 85, 78, 40,
                            228, 138, 192, 115, 114, 149, 70
                        };
            string passwd = "SafeP4ssw0rd;,,:;DWAe";
            string getXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(encryptedPublicKeyXmlStringFromSomewhere, passwd, salt, IV))
                {
                    getXmlString = packer.ToXmlString(true);
                }
            }

            Assert.IsNotNull(getXmlString);
        }
        [TestMethod]
        public void Instantiate_PassXmlString_Pass()
        {
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string getXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    getXmlString = packer.ToXmlString(true);
                }
            }

            Assert.IsNotNull(getXmlString);
        }
        [TestMethod]
        public void GetConfigXmlString_PassXmlStringAndGenerateConfigXmlString_Pass()
        {
            string aesCipherXmlString;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    aesCipherXmlString = packer.GetConfigXmlString(aesCipher);
                }
            }

            Assert.IsNotNull(aesCipherXmlString);
        }
        [TestMethod]
        public void SetConfigXmlString_PassXmlStringAndGenerateConfigXmlString_Pass()
        {
            string HalloString = "BKx3eFnXDp55QoDdKSutjw==";
            string Hallo = "Hallo";
            string configString = symConfigXmlString;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string decryptedString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.ApplyConfigXmlString(aesCipher, configString);
                    
                }
                decryptedString = aesCipher.DecryptToString(HalloString);
            }

            Assert.AreEqual(Hallo, decryptedString);
        }
        [TestMethod]
        public void GetSetConfigXmlString_TransferSymmetricConfigForCryption_Pass()
        {
            string plainText = "Hallo my Freund!";
            byte[] encrypted;
            string decryptedText;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string configXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                aesCipher.Encoding = Encoding.Default;
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    configXmlString = packer.GetConfigXmlString(aesCipher);
                }
                encrypted = aesCipher.Encrypt(plainText);
            }

            using(var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using(KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.ApplyConfigXmlString(aesCipher, configXmlString);
                }
                decryptedText = aesCipher.DecryptToString(encrypted);
            }

            Assert.AreEqual(plainText, decryptedText);
        }
        [TestMethod]
        public void GetSetConfigXmlString_SetEncodingDefaultAndCheck_Pass()
        {
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string configXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                aesCipher.Encoding = Encoding.Default;
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    configXmlString = packer.GetConfigXmlString(aesCipher);
                }
            }

            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.ApplyConfigXmlString(aesCipher, configXmlString);
                }

                if (!configXmlString.Contains("Default"))
                    Assert.Fail("config xml does not contain Default Encoding");
                else
                    Assert.AreEqual(Encoding.Default, aesCipher.Encoding);
            }
        }
        [TestMethod]
        public void GetVitalConfig_GetKeyAndEncryptedIVFromMethod_Pass()
        {
            byte[] key;
            byte[] iv;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.GetVitalConfig(aesCipher, out key, out iv, true);
                }
            }

            Assert.IsNotNull(key);
        }
        [TestMethod]
        public void SetVitalConfig_GetKeyAndEncryptedIVFromMethod_Pass()
        {
            byte[] key;
            byte[] iv;
            bool decryptIV = true;
            string plainString = "I am going to get encrypted!";
            string encryptedString;
            string decryptedString;

            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.GetVitalConfig(aesCipher, out key, out iv, decryptIV);
                }
                encryptedString = aesCipher.EncryptToString(plainString);
            }

            using(var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (KeyPacker packer = new KeyPacker(plainXmlStringFromSomewhere))
                {
                    packer.SetVitalConfig(aesCipher, key, iv, decryptIV);
                }
                decryptedString = aesCipher.DecryptToString(encryptedString);
            }

            Assert.AreEqual(plainString, decryptedString);
        }
        [TestMethod]
        public void CreateCipher_CreateCipherWithStaticMethod_Pass()
        {
            string configString = symConfigXmlString;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            using (var aesCipher = KeyPacker
                .CreateCipher<AesManaged>(plainXmlStringFromSomewhere,
                                            configString))
            {
                Assert.IsNotNull(aesCipher);
            }
        }
        [TestMethod]
        public void GetMinimalConfigXmlString_CreateCipherWithStaticMethod_Pass()
        {
            string configString = symConfigXmlString;
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string minimalConfig;
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using(var packer = new KeyPacker(rsaPlainXmlString))
                {
                    minimalConfig = packer.GetMinimalConfigXmlString(aesCipher);
                }
            }
            Assert.IsNotNull(minimalConfig);
        }
        [TestMethod]
        public void ApplyMinimalConfigXmlString_CreateCipherWithStaticMethod_Pass()
        {
            string plainXmlStringFromSomewhere = rsaPlainXmlString;
            string minimalConfig;
            string plainText = "I am going to get encrypted!";
            string encryptedText;
            string decryptedText;

            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (var packer = new KeyPacker(rsaPlainXmlString))
                {
                    minimalConfig = packer.GetMinimalConfigXmlString(aesCipher);
                }
                encryptedText = aesCipher.EncryptToString(plainText);
            }
            using (var aesCipher = new SymmetricCipher<AesManaged>())
            {
                using (var packer = new KeyPacker(rsaPlainXmlString))
                {
                    packer.ApplyMinimalConfigXmlString(aesCipher, minimalConfig);
                }
                decryptedText = aesCipher.DecryptToString(encryptedText);
            }

            Assert.AreEqual(plainText, decryptedText);
        }
    }
}
