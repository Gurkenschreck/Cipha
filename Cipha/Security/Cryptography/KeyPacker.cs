using Cipha.Security.Cryptography.Asymmetric;
using Cipha.Security.Cryptography.Symmetric;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Cipha.Security.Cryptography
{
    public class KeyPacker : IDisposable
    {
        protected bool rsaDisposeNeeded = false;
        protected RSACipher<RSACryptoServiceProvider> rsa;

        /// <summary>
        /// Gets the current rsa csp instance.
        /// </summary>
        public RSACipher<RSACryptoServiceProvider> RSACipher
        {
            get
            {
                return rsa;
            }
        }

        /// <summary>
        /// Exports the current configuration as plaintext in xml format.
        /// </summary>
        /// <param name="includePrivateKey">If the exported configuration should contain the private key information.</param>
        /// <returns>The configuration string in plaintext.</returns>
        public string ToXmlString(bool includePrivateKey)
        {
            return rsa.ToXmlString(includePrivateKey);
        }
        /// <summary>
        /// Applies the given configuration string to the current object.
        /// </summary>
        /// <param name="encryptedXmlString">The xml configuration string.</param>
        public void FromXmlString(string xmlString)
        {
            rsa.FromXmlString(xmlString);
        }

        public string ToEncryptedXmlString<U>(bool includePrivateKey, string password, byte[] salt, out byte[] IV, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new()
        {
            using (var symAlgo = new SymmetricCipher<U>(password, salt, null, keySize, iterationCount))
            {
                IV = (byte[])symAlgo.IV.Clone();
                return symAlgo.EncryptToString(rsa.ToXmlString(includePrivateKey));
            }
        }
        public string ToEncryptedXmlString<U>(bool includePrivateKey, string symmetricConfigXmlString, bool decryptIV = true)
            where U : SymmetricAlgorithm, new()
        {
            using (var symAlgo = CreateCipher<U>(symmetricConfigXmlString, decryptIV))
            {
                return symAlgo.EncryptToString(rsa.ToXmlString(includePrivateKey));
            }
        }
        public void FromEncryptedXmlString<U>(string encryptedXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int iterationCount = 10000)
            where U : SymmetricAlgorithm, new()
        {
            using (var symAlgo = new SymmetricCipher<U>(password, salt, IV, keySize, iterationCount))
            {
                rsa.FromXmlString(symAlgo.DecryptToString(encryptedXmlString));
            }
        }
        public void FromEncryptedXmlString<U>(string encryptedXmlString, string symmetricConfigXmlString, bool decryptIV = true)
           where U : SymmetricAlgorithm, new()
        {
            using (var symAlgo = CreateCipher<U>(symmetricConfigXmlString, decryptIV))
            {
                rsa.FromXmlString(symAlgo.DecryptToString(encryptedXmlString));
            }
        }

        /// <summary>
        /// Creates a new instance and a new RSA object with the
        /// specified key size.
        /// </summary>
        /// <param name="keySize">The key size in bits.</param>
        public KeyPacker(int keySize = 2048)
        {
            rsa = new RSACipher<RSACryptoServiceProvider>(keySize);
            rsaDisposeNeeded = true;
        }
        public KeyPacker(string clearXmlString)
        {
            rsa = new RSACipher<RSACryptoServiceProvider>(clearXmlString);
            rsaDisposeNeeded = true;
        }
        public KeyPacker(string encryptedPublicKeyXmlString, string password, byte[] salt, byte[] IV, int keySize = 0, int iterationCount = 10000)
        {
            rsa = new RSACipher<RSACryptoServiceProvider>(encryptedPublicKeyXmlString, password, salt, IV, keySize, iterationCount);
            rsaDisposeNeeded = true;
        }

        protected byte[] Encrypt(byte[] plainData)
        {
            return rsa.Encrypt(plainData);
        }
        protected byte[] Encrypt(string plainData)
        {
            return rsa.Encrypt(plainData);
        }
        protected string EncryptToString(string plainData)
        {
            return rsa.EncryptToString(plainData);
        }
        protected string EncryptToString(byte[] plainData)
        {
            return rsa.EncryptToString(plainData);
        }

        protected byte[] Decrypt(byte[] cipherData)
        {
            return rsa.Decrypt(cipherData);
        }
        protected byte[] Decrypt(string cipherData)
        {
            return rsa.Decrypt(cipherData);
        }

        /// <summary>
        /// Creates a new SymmetricCipher and configures it
        /// with the provided configuration string right away.
        /// </summary>
        /// <typeparam name="T">The SymmetricAlgorithm to use.</typeparam>
        /// <param name="rsaConfigXmlString">The rsa xml configuration string.</param>
        /// <param name="symmetricConfigXmlString">The xml configuration string to apply.</param>
        /// <returns></returns>
        public static SymmetricCipher<T> CreateCipher<T>(string rsaConfigXmlString, string symmetricConfigXmlString)
            where T : SymmetricAlgorithm, new()
        {
            var symCipher = new SymmetricCipher<T>(new T());

            using(var rsaCipher = new RSACipher<RSACryptoServiceProvider>(rsaConfigXmlString))
            {
                using(var packer = new KeyPacker(rsaConfigXmlString))
                {
                    packer.ApplyConfigXmlString(symCipher, symmetricConfigXmlString);
                }
            }
            return symCipher;
        }
        public SymmetricCipher<T> CreateCipher<T>(string symmetricConfigXmlString, bool decryptIV = true)
            where T : SymmetricAlgorithm, new()
        {
            var symCipher = new SymmetricCipher<T>(new T());
            ApplyConfigXmlString(symCipher, symmetricConfigXmlString, decryptIV);
            return symCipher;
        }

        /// <summary>
        /// Outputs the cryptographic essential key and IV
        /// in encrypted format.
        /// </summary>
        /// <param name="symmetricCipher">The symmetricCipher to extract the key and IV from.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        /// <param name="iv">The possibly encrypted IV.</param>
        /// <param name="encryptIVAlso">If the IV should also be encrypted.</param>
        public virtual void GetVitalConfig(Cipher symmetricCipher, out byte[] encryptedKey, out byte[] iv, bool encryptIVAlso = false)
        {
            dynamic cipher = symmetricCipher;

            GetVitalConfig(cipher.Algorithm, out encryptedKey, out iv, encryptIVAlso);
        }
        /// <summary>
        /// Outputs the cryptographic essential key and IV
        /// in encrypted format.
        /// </summary>
        /// <param name="symmetricCipher">The symmetricCipher to extract the key and IV from.</param>
        /// <param name="encryptedKey">The encrypted key.</param>
        /// <param name="iv">The possibly encrypted IV.</param>
        /// <param name="encryptIVAlso">If the IV should also be encrypted.</param>
        public virtual void GetVitalConfig(SymmetricAlgorithm symmetricCipher, out byte[] encryptedKey, out byte[] iv, bool encryptIVAlso = false)
        {
            dynamic cipher = symmetricCipher;

            encryptedKey = Encrypt(cipher.Key);
            if (encryptIVAlso)
                iv = Encrypt(cipher.IV);
            else
                iv = cipher.IV;
        }

        /// <summary>
        /// Decrypts the key and IV if neccessary and applies it to
        /// the symmetric symmetricCipher.
        /// </summary>
        /// <param name="symmetricCipher"></param>
        /// <param name="encryptedKey"></param>
        /// <param name="iv"></param>
        /// <param name="decryptIVAlso"></param>
        public virtual void SetVitalConfig(Cipher symmetricCipher, byte[] encryptedKey, byte[] iv, bool decryptIVAlso = false)
        {
            dynamic cipher = symmetricCipher;
            SetVitalConfig(cipher.Algorithm, encryptedKey, iv, decryptIVAlso);
        }
        public virtual void SetVitalConfig(SymmetricAlgorithm symmetricCipher, byte[] encryptedKey, byte[] iv, bool decryptIVAlso = false)
        {
            dynamic cipher = symmetricCipher;
            cipher.Key = Decrypt(encryptedKey);
            if (decryptIVAlso)
                cipher.IV = Decrypt(iv);
            else
                cipher.IV = iv;
        }

        /// <summary>
        /// Creates a xml string to transport
        /// symmetric symmetricCipher configurations.
        /// 
        /// The key is encrypted using the current
        /// RSA configuration.
        /// </summary>
        /// <param name="symmetricCipher">The SymmetricCipher to extract its config from.</param>
        /// <returns>The xml configuration string.</returns>
        public virtual string GetConfigXmlString(Cipher symmetricCipher, bool encryptIV = true)
        {
            dynamic cipher = symmetricCipher;
            return string.Format("<SymmetricCipher>"
                + "<EncryptedKey>{0}</EncryptedKey>"
                + "<IV>{1}</IV>"
                + "<BlockSize>{2}</BlockSize>"
                + "<Salt>{3}</Salt>"
                + "<Iterations>{4}</Iterations>"
                + "<Encoding>{5}</Encoding>"
                + "</SymmetricCipher>",
                EncryptToString(cipher.Key),
                encryptIV ? EncryptToString(cipher.IV) : Convert.ToBase64String(cipher.IV),
                cipher.BlockSize,
                cipher.Salt != null
                    ? cipher.Salt : "",
                cipher.HashIterations,
                cipher.Encoding == Encoding.Default
                    ? "Default" : cipher.Encoding);
        }

        /// <summary>
        /// Creates a xml configuration string containing only
        /// the encrypted key and the IV.
        /// The IV is encrypted by default. This is set via the
        /// encryptIV parameter.
        /// </summary>
        /// <param name="symmetricCipher">The symmetric cipher to create the configuration from.</param>
        /// <param name="encryptIV">If the IV should also be encrypted.</param>
        /// <returns>The minimal configuration string in xml format.</returns>
        public virtual string GetMinimalConfigXmlString(Cipher symmetricCipher, bool encryptIV = true)
        {
            dynamic cipher = symmetricCipher;
            return GetMinimalConfigXmlString(cipher.Algorithm, encryptIV);
        }

        /// <summary>
        /// Creates a xml configuration string containing only
        /// the encrypted key and the IV.
        /// The IV is encrypted by default. This is set via the
        /// encryptIV parameter.
        /// </summary>
        /// <param name="symmetricCipher">The symmetric cipher to create the configuration from.</param>
        /// <param name="encryptIV">If the IV should also be encrypted.</param>
        /// <returns>The minimal configuration string in xml format.</returns>
        public virtual string GetMinimalConfigXmlString(SymmetricAlgorithm symmetricAlgorithm, bool encryptIV = true)
        {
            return string.Format("<SymmetricCipher>"
                + "<EncryptedKey>{0}</EncryptedKey>"
                + "<IV>{1}</IV>"
                + "</SymmetricCipher>",
                EncryptToString(symmetricAlgorithm.Key),
                encryptIV ? EncryptToString(symmetricAlgorithm.IV) : Convert.ToBase64String(symmetricAlgorithm.IV));
        }

        /// <summary>
        /// Applies a previouly generated xml configuration
        /// string.
        /// 
        /// The key is decrypted using the current RSA
        /// configuration.
        /// </summary>
        /// <param name="symmetricCipher">The symmetricCipher to apply the config to.</param>
        /// <param name="configString">The xml configuration string.</param>
        public virtual void ApplyConfigXmlString(Cipher symmetricCipher, string configString, bool decryptIV = true)
        {
            dynamic dynCipher = symmetricCipher;
            XDocument xdoc = XDocument.Parse(configString);
            XElement rootElement = xdoc.Root;
            string key;
            string IV;
            int blockSize;
            string salt;
            int iterations;
            string encoding;

            // Check for malformation and extract data
            if (rootElement.Element("EncryptedKey") == null)
                throw new MalformedXmlConfigStringException("EncryptedKey missing");
            key = rootElement.Element("EncryptedKey").Value;
            if (rootElement.Element("IV") == null)
                throw new MalformedXmlConfigStringException("IV missing");
            IV = rootElement.Element("IV").Value;
            if (rootElement.Element("BlockSize") == null)
                throw new MalformedXmlConfigStringException("BlockSize missing");
            blockSize = Convert.ToInt32(rootElement.Element("BlockSize").Value);
            if (rootElement.Element("Salt") == null)
                throw new MalformedXmlConfigStringException("Salt missing");
            salt = rootElement.Element("Salt").Value;
            if (rootElement.Element("Iterations") == null)
                throw new MalformedXmlConfigStringException("Iterations missing");
            iterations = Convert.ToInt32(rootElement.Element("Iterations").Value);
            if (rootElement.Element("Encoding") == null)
                throw new MalformedXmlConfigStringException("Encoding missing");
            encoding = rootElement.Element("Encoding").Value;

            // Apply
            dynCipher.Key = Decrypt(key);
            dynCipher.IV = decryptIV ? Decrypt(IV) : Convert.FromBase64String(IV);
            dynCipher.BlockSize = blockSize;
            if (!string.IsNullOrEmpty(salt))
                dynCipher.Salt = salt;
            dynCipher.HashIterations = iterations;
            dynCipher.Encoding = GetRightEncoding(encoding);
        }

        /// <summary>
        /// Applies the minimal configuration string to the
        /// provided cipher.
        /// </summary>
        /// <param name="symmetricCipher">The cipher to apply the configuration.</param>
        /// <param name="configString">The minimal configuration string.</param>
        /// <param name="decryptIV">If the IV should be decrypted.</param>
        public virtual void ApplyMinimalConfigXmlString(Cipher symmetricCipher, string configString, bool decryptIV = true)
        {
            dynamic dynCipher = symmetricCipher;
            ApplyMinimalConfigXmlString(dynCipher.Algorithm, configString, decryptIV);
        }

        /// <summary>
        /// Applies the minimal configuration string to the
        /// provided cipher.
        /// </summary>
        /// <param name="symmetricAlgorithm">The cipher to apply the configuration.</param>
        /// <param name="configString">The minimal configuration string.</param>
        /// <param name="decryptIV">If the IV should be decrypted.</param>
        public virtual void ApplyMinimalConfigXmlString(SymmetricAlgorithm symmetricAlgorithm, string configString, bool decryptIV = true)
        {
            XDocument xdoc = XDocument.Parse(configString);
            XElement rootElement = xdoc.Root;
            string key;
            string IV;

            // Check for malformation and extract data
            if (rootElement.Element("EncryptedKey") == null)
                throw new MalformedXmlConfigStringException("EncryptedKey missing");
            key = rootElement.Element("EncryptedKey").Value;
            if (rootElement.Element("IV") == null)
                throw new MalformedXmlConfigStringException("IV missing");
            IV = rootElement.Element("IV").Value;

            // Apply
            symmetricAlgorithm.Key = Decrypt(key);
            symmetricAlgorithm.IV = (decryptIV) ? Decrypt(IV) : Convert.FromBase64String(IV);
        }

        protected Encoding GetRightEncoding(string classString)
        {
            switch(classString)
            {
                case "System.Text.UTF8Encoding":
                    return Encoding.UTF8;
                case "System.Text.UTF7Encoding":
                    return Encoding.UTF7;
                case "System.Text.UTF32Encoding":
                    return Encoding.UTF32;
                case "System.Text.ASCIIEncoding":
                    return Encoding.ASCII;
                case "System.Text.UnicodeEncoding":
                    return Encoding.Unicode;
                case "Default":
                    return Encoding.Default;
                default:
                    throw new InvalidCastException(classString + " cannot be converted to Encoding type");
            }
        }
        ~KeyPacker()
        {
            Dispose(false);
            GC.SuppressFinalize(this);
        }
        public void Dispose()
        {
            Dispose(true);
        }
        protected void Dispose(bool disposing)
        {
            if(disposing)
            {
                if (rsaDisposeNeeded)
                    rsa.Dispose();
            }
        }
    }
}
