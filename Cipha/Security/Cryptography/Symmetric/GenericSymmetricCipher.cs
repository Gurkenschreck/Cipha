using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Symmetric
{
    /// <summary>
    /// The GenericSymmetricCipher class provides
    /// an easy interface for interacting with all
    /// classes inheriting SymmetricAlgorithm.
    /// 
    /// Possible classes include, but are not limited to:
    ///     RijndaelManaged
    ///     AesManaged
    ///     RC2CryptoServiceProvider
    ///     DESCryptoServiceProvider
    ///     TrippleDESCryptoServiceProvider
    ///     
    /// located in the System.Security.Cryptography namespace.
    /// 
    /// The standard encoding of the strings is UTF8 but can be
    /// changed via the property Encoding.
    /// </summary>
    /// <typeparam name="T">The specific SymmetricAlgorithm to be used for en- and decryption.</typeparam>
    public class GenericSymmetricCipher<T>
        where T : SymmetricAlgorithm, new()
    {
        private int? keySize;
        /// <summary>
        /// The KeySize which should be used for 
        /// en- and decryption.
        /// </summary>
        public int? KeySize
        {
            get { return keySize; }
            set 
            {
                if (value == null)
                    throw new InvalidOperationException("new keysize value is null");

                using(SymmetricAlgorithm algo = new T())
                {
                    if (algo.ValidKeySize((int)value))
                    {
                        keySize = value;

                    }
                    else
                        throw new CryptographicException("invalid new keysize");
                }
            }
        }

        private Encoding encoding = Encoding.Default;
        /// <summary>
        /// The standard string encoding used.
        /// Default is Encoding.UTF8.
        /// </summary>
        public Encoding Encoding
        {
            get { return encoding; }
            set 
            {
                if (value == null)
                    throw new InvalidOperationException("encoding cannot be set to null");
                encoding = value; 
            }
        }


        /// <summary>
        /// Provides help encrypting a string with any encryption algorithm
        /// extending from SymmetricAlgorithm.
        /// Possible algorithms to use are
        /// AesManages, TripleDESCryptoServiceprovider, RijndaelManaged
        /// </summary>
        /// <param name="plainString">The Unicode string to encrypt.</param>
        /// <param name="password">The password to encrypt.</param>
        /// <param name="salt">The salt to encrypt.</param>
        /// <returns></returns>
        public string Encrypt(string plainString, string password, string salt)
        {
            return encoding.GetString(Encrypt(encoding.GetBytes(plainString), password, salt));
        }

        /// <summary>
        /// Provides help encrypting a string with any encryption algorithm
        /// extending from SymmetricAlgorithm.
        /// Possible algorithms to use are
        /// AesManages, TripleDESCryptoServiceprovider, RijndaelManaged
        /// </summary>
        /// <typeparam name="T">The subclass of SymmetricAlgorithm.</typeparam>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainData, string password, string salt)
        {
            if (plainData == null)
                throw new ArgumentNullException("plainData");
            if (password == null)
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");

            DeriveBytes rgb = new Rfc2898DeriveBytes(password, encoding.GetBytes(salt));

            SymmetricAlgorithm algorithm = new T();

            SetKeySize(algorithm, keySize);

            byte[] rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

            ICryptoTransform transform = algorithm.CreateEncryptor(rgbKey, rgbIV);

            using (MemoryStream buffer = new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
                {
                    using (StreamWriter writer = new StreamWriter(stream, encoding))
                    {
                        writer.Write(encoding.GetString(plainData));
                    }
                }
                algorithm.Dispose();
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Decrypts a cipherString by using the password and salt.
        /// 
        /// The character encoding can be changed via the
        /// property Encoding.
        /// </summary>
        /// <param name="cipherString">The previously encrypted string.</param>
        /// <param name="password">The password to decrypt.</param>
        /// <param name="salt">The salt used for decryption.</param>
        /// <returns>The decrypted string.</returns>
        public string Decrypt(string cipherString, string password, string salt)
        {
            return encoding.GetString(Decrypt(encoding.GetBytes(cipherString), password, salt));
        }

        /// <summary>
        /// Provides help decrypting a string with any encryption algorithm
        /// extending from SymmetricAlgorithm.
        /// Possible algorithms to use are
        /// AesManages, TripleDESCryptoServiceprovider, RijndaelManaged
        /// </summary>
        /// <typeparam name="T">The algorithm deriving from SymmetricAlgorithm.</typeparam>
        /// <param name="cipherData">The previously encrypted plain data.</param>
        /// <param name="password">The password to decrypt.</param>
        /// <param name="salt">The salt used to encrypt the data.</param>
        /// <returns>The decrypted bytes.</returns>
        public byte[] Decrypt(byte[] cipherData, string password, string salt)
        {
            if (cipherData == null)
                throw new ArgumentNullException("cipherData");
            if (password == null)
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, encoding.GetBytes(salt));

            SymmetricAlgorithm algorithm = new T();

            SetKeySize(algorithm, KeySize);

            byte[] rgbKey = rgb.GetBytes(algorithm.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algorithm.BlockSize >> 3);

            ICryptoTransform transform = algorithm.CreateDecryptor(rgbKey, rgbIV);

            using (MemoryStream buffer = new MemoryStream(cipherData))
            {
                using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(stream, encoding))
                    {
                        algorithm.Dispose();
                        return encoding.GetBytes(reader.ReadToEnd());
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts a file using the SymmetricAlgorithm T.
        /// 
        /// If you do not have a key or iv, pass null for both,
        /// those references will be filled with the key and
        /// iv used in the process.
        /// 
        /// When only a key or a iv is given, it is not used.
        /// 
        /// Store the generated key and iv for later decryption.
        /// </summary>
        /// <param name="inFile">The file to read.</param>
        /// <param name="outFile">The output file.</param>
        /// <param name="key">The key to use. Passing null generates a key.</param>
        /// <param name="iv"></param>
        public void EncryptFile(string inFile, string outFile, ref byte[] key, ref byte[] iv)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using(FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                //Create variables to help with read and write.
                int bufferLength = 100;
                byte[] bin = new byte[bufferLength]; //This is intermediate storage for the encryption.
                long rdlen = 0;              //This is the total number of bytes written.
                long totlen = fIn.Length;    //This is the total length of the input file.
                int len;                    //This is the number of bytes to be written at a time.

                using (SymmetricAlgorithm algo = new T())
                {
                    SetKeySize(algo, keySize);

                    if (key != null && iv != null)
                    {
                        algo.Key = key;
                        algo.IV = iv;
                    }
                    else
                    {
                        key = algo.Key;
                        iv = algo.IV;
                    }
                    
                    using(FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                    {                    
                        using(CryptoStream encStream = new CryptoStream(fOut, algo.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            while (rdlen < totlen)
                            {
                                len = fIn.Read(bin, 0, bufferLength);
                                encStream.Write(bin, 0, len);
                                rdlen = rdlen + len;
                            }
                        }
                    }
                }
            }
        }
        
        /// <summary>
        /// Decrypts a file which was previously encrypted
        /// with the alogrithm T.
        /// </summary>
        /// <param name="inFile">The encrypted file.</param>
        /// <param name="outFile">The output file.</param>
        /// <param name="key">The key used.</param>
        /// <param name="iv">The iv used.</param>
        public void DecryptFile(string inFile, string outFile, byte[] key, byte[] iv)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using (FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                //Create variables to help with read and write.
                int bufferLength = 100;
                byte[] bin = new byte[bufferLength]; //This is intermediate storage for the encryption.
                long totlen = fIn.Length;    //This is the total length of the input file.

                using (SymmetricAlgorithm algo = new T())
                {
                    SetKeySize(algo, keySize);

                    if (key != null && iv != null)
                    {
                        algo.Key = key;
                        algo.IV = iv;
                    }
                    
                    using (FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        using (CryptoStream decStream = new CryptoStream(fIn, algo.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            // read byte for byte
                            int bytee = 0;
                            while(((bytee = decStream.ReadByte()) != -1))
                            {
                                fOut.WriteByte((byte)bytee);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Sets the keysize of the SymmetricAlgorithm if a
        /// size is given.
        /// 
        /// The size can be changed via the KeySize property of
        /// this class.
        /// 
        /// Throws CryptographicException if the keySize is invalid.
        /// </summary>
        /// <param name="algo">The algorithm to change the keysize.</param>
        /// <param name="keySize">The keysize to set.</param>
        private void SetKeySize(SymmetricAlgorithm algo, int? keySize)
        {
            if (keySize != null)
            {
                if (algo.ValidKeySize((int)keySize))
                {
                    algo.KeySize = (int)keySize;
                }
                else
                {
                    throw new System.Security.Cryptography.CryptographicException("Invalid KeySize: " + keySize);
                }
            }
        }
    }
}
