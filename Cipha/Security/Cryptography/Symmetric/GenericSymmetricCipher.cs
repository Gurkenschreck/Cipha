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
    /// 
    /// GenericSymmetricCipher does not hold any sensitive data.
    /// Each time a Method is called, a new instance of the
    /// symmetric algorithm is created, whose values is set
    /// to the previously set properties of this class.
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
                    throw new ArgumentNullException("value");

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

        private int rfc2898Iterations = 1000;
        /// <summary>
        /// Some methods use the Rfc2898 implementation of the
        /// PBKDF2 algorithm. 
        /// 
        /// This algorithm uses a password and a salt to apply
        /// multiple hashes.
        /// 
        /// Default:
        ///     1000
        /// </summary>
        public int Rfc2898Iterations
        {
            get { return rfc2898Iterations; }
            set { rfc2898Iterations = value; }
        }

        private int? blockSize;
        /// <summary>
        /// The block size to be used by the
        /// algorithm.
        /// </summary>
        public int? BlockSize
        {
            get { return blockSize; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                using (SymmetricAlgorithm algo = new T())
                {
                    if (Utilities.ValidSymmetricBlockSize(algo, (int)value))
                    {
                        blockSize = value;
                    }
                    else
                        throw new CryptographicException("invalid new block size");
                }
            }
        }

        /// <summary>
        /// Returns the legal plainData sizes for the
        /// specified symmetric algorithm.
        /// </summary>
        public KeySizes[] LegalKeySizes
        {
            get
            {
                using (SymmetricAlgorithm algo = new T())
                {
                    return algo.LegalKeySizes;
                }
            }
        }

        /// <summary>
        /// Returns the legal block sizes for the
        /// specified symmetric algorithm.
        /// </summary>
        public KeySizes[] LegalBlockSizes
        {
            get
            {
                using(SymmetricAlgorithm algo = new T())
                {
                    return algo.LegalBlockSizes;
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
                    throw new ArgumentNullException("value");
                encoding = value; 
            }
        }

        private PaddingMode padding = PaddingMode.PKCS7;
        /// <summary>
        /// The padding to be used in the cryptographic
        /// processes.
        /// </summary>
        public PaddingMode Padding
        {
            get { return padding; }
            set
            {
                padding = value;
            }
        }

        private CipherMode mode = CipherMode.CBC;
        /// <summary>
        /// The CipherMode which shall be used
        /// in the cryptographic process.
        /// </summary>
        public CipherMode Mode
        {
            get { return mode; }
            set
            {
                mode = value;
            }
        }


        /// <summary>
        /// Encrypts a plain string.
        /// Returns the encrypted data as a base64 String.
        /// </summary>
        /// <param name="cipherData">The Unicode string to encrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt to encrypt.</param>
        /// <returns>The encrypted base64 string.</returns>
        public string EncryptToString(string plainString, string password, string salt)
        {
            return Convert.ToBase64String(Encrypt(encoding.GetBytes(plainString), encoding.GetBytes(password), encoding.GetBytes(salt)));
        }
        /// <summary>
        /// Encrypts plain data and converts it to a base 64 string.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt to use.</param>
        /// <returns>The encrypted data.</returns>
        public string EncryptToString(byte[] plainData, byte[] password, byte[] salt)
        {
            return Convert.ToBase64String(Encrypt(plainData, password, salt));
        }

        /// <summary>
        /// Encrypts a blob of bytes.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt to use.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plainData, string password, string salt)
        {
            return Encrypt(plainData, encoding.GetBytes(password), encoding.GetBytes(salt));
        }

        /// <summary>
        /// Encrypts a blob of bytes.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plainData, string password, byte[] salt)
        {
            return Encrypt(plainData, encoding.GetBytes(password), salt);
        }

        /// <summary>
        /// Provides help encrypting a string with any encryption algorithm
        /// extending from SymmetricAlgorithm.
        /// </summary>
        /// <typeparam name="T">The subclass of SymmetricAlgorithm.</typeparam>
        /// <param name="cipherData">The plain data to encrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt to be used.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainData, byte[] password, byte[] salt)
        {
            if (plainData == null)
                throw new ArgumentNullException("plainData");
            if (password == null)
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");

            DeriveBytes rgb = new Rfc2898DeriveBytes(password, salt, rfc2898Iterations);

            SymmetricAlgorithm algo = new T();
            
            ApplyConfigurations(algo);

            byte[] rgbKey = rgb.GetBytes(algo.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algo.BlockSize >> 3);

            ICryptoTransform transform = algo.CreateEncryptor(rgbKey, rgbIV);

            using (MemoryStream buffer = new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
                {
                    using (StreamWriter writer = new StreamWriter(stream, encoding))
                    {
                        writer.Write(Convert.ToBase64String(plainData));
                    }
                }
                return buffer.ToArray();
            }
        }

        /// <summary>
        /// Decrypts a cipherData by using the password and salt.
        /// 
        /// The character encoding can be changed via the
        /// property Encoding.
        /// </summary>
        /// <param name="cipherData">The previously encrypted string.</param>
        /// <param name="password">The password to decrypt.</param>
        /// <param name="salt">The salt used for decryption.</param>
        /// <returns>The decrypted string.</returns>
        public byte[] Decrypt(string cipherString, string password, string salt)
        {
            return Decrypt(encoding.GetBytes(cipherString), password, encoding.GetBytes(salt));
        }

        /// <summary>
        /// Provides help decrypting a string with any encryption algo
        /// extending from SymmetricAlgorithm.
        /// </summary>
        /// <typeparam name="T">The algo deriving from SymmetricAlgorithm.</typeparam>
        /// <param name="cipherData">The previously encrypted plain data.</param>
        /// <param name="password">The password to decrypt.</param>
        /// <param name="salt">The salt used to encrypt the data.</param>
        /// <returns>The decrypted bytes.</returns>
        public byte[] Decrypt(byte[] cipherData, string password, byte[] salt)
        {
            if (cipherData == null)
                throw new ArgumentNullException("cipherData");
            if (password == null)
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, salt, rfc2898Iterations);

            SymmetricAlgorithm algo = new T();
            ApplyConfigurations(algo);

            byte[] rgbKey = rgb.GetBytes(algo.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algo.BlockSize >> 3);

            algo.Dispose();

            return Decrypt(cipherData, rgbKey, rgbIV);
        }

        /// <summary>
        /// Provides help decrypting a string with any encryption algo
        /// extending from SymmetricAlgorithm.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <param name="plainData">The plainData used in the encryption.</param>
        /// <param name="IV">the IV used in the encryption.</param>
        /// <returns>The decrypted blob.</returns>
        public byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            if (cipherData == null)
                throw new ArgumentNullException("cipherData");
            if (key == null)
                throw new ArgumentNullException("plainData");
            if (iv == null)
                throw new ArgumentNullException("iv");
            
            SymmetricAlgorithm algo = new T();

            ApplyConfigurations(algo);

            algo.Key = key;
            algo.IV = iv;

            using (MemoryStream buffer = new MemoryStream(cipherData))
            {
                using (CryptoStream stream = new CryptoStream(buffer, algo.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(stream, encoding))
                    {
                        algo.Dispose();
                        return Convert.FromBase64String(reader.ReadToEnd());
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a cipher string
        /// </summary>
        /// <param name="cipherData">The string to decrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        public string DecryptToString(string cipherData, string password, string salt)
        {
            return encoding.GetString(Decrypt(Convert.FromBase64String(cipherData), password, encoding.GetBytes(salt)));
        }

        /// <summary>
        /// Decrypts an encrypted blob of bytes.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        public string DecryptToString(byte[] cipherData, string password, string salt)
        {
            return Convert.ToBase64String(Decrypt(cipherData, password, encoding.GetBytes(salt)));
        }


        /// <summary>
        /// Encrypts a file by creating a plainData and IV
        /// for the provided password and salt.
        /// 
        /// The amount of iterations of the Rfc2898
        /// algorithm is set via the property
        /// Rfc2898Iterations.
        /// </summary>
        /// <param name="inFile">The file to encrypt.</param>
        /// <param name="outFile">The file to decrypt.</param>
        /// <param name="password">The password to use in the plainData derivation keyDerivationFunction.</param>
        /// <param name="salt">The salt used in the encryption process.</param>
        public void EncryptFile(string inFile, string outFile, string password, string salt)
        {
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, encoding.GetBytes(salt), rfc2898Iterations);
            

            SymmetricAlgorithm algo = new T();

            byte[] rgbKey = rgb.GetBytes(algo.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algo.BlockSize >> 3);

            algo.Dispose();

            EncryptFile(inFile, outFile, ref rgbKey, ref rgbIV);
        }

        /// <summary>
        /// Encrypts a file using the SymmetricAlgorithm T.
        /// 
        /// If you do not have a plainData or IV, pass null for both,
        /// those references will be filled with the plainData and
        /// IV used in the process.
        /// 
        /// When only a plainData or a IV is given, it is not used.
        /// 
        /// Store the generated plainData and IV for later decryption.
        /// </summary>
        /// <param name="inFile">The file to read.</param>
        /// <param name="outFile">The output file.</param>
        /// <param name="plainData">The plainData to use.</param>
        /// <param name="IV">The IV to use.</param>
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
                    ApplyConfigurations(algo);

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
        /// Decrypts a file using a password and a salt.
        /// </summary>
        /// <param name="inFile">The file to decrypt.</param>
        /// <param name="outFile">The output file.</param>
        /// <param name="password">The password to use.</param>
        /// <param name="salt">The salt to use.</param>
        public void DecryptFile(string inFile, string outFile, string password, string salt)
        {
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, encoding.GetBytes(salt), rfc2898Iterations);

            SymmetricAlgorithm algo = new T();

            ApplyConfigurations(algo);

            byte[] rgbKey = rgb.GetBytes(algo.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(algo.BlockSize >> 3);

            algo.Dispose();

            DecryptFile(inFile, outFile, ref rgbKey, ref rgbIV);
        }

        /// <summary>
        /// Decrypts a file which was previously encrypted
        /// with the alogrithm T.
        /// </summary>
        /// <param name="inFile">The encrypted file.</param>
        /// <param name="outFile">The output file.</param>
        /// <param name="plainData">The plainData used.</param>
        /// <param name="IV">The IV used.</param>
        public void DecryptFile(string inFile, string outFile, ref byte[] key, ref byte[] iv)
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
                    ApplyConfigurations(algo);

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
        /// Sets the configuration of the SymmetricAlgorithm.
        /// </summary>
        /// <param name="algo">The algorithm to configure.</param>
        private void ApplyConfigurations(SymmetricAlgorithm algo)
        {
            // Set padding
            if (algo.Padding != padding)
                algo.Padding = padding;

            // Set current CipherMode
            if (algo.Mode != mode)
                algo.Mode = mode;

            // Set the block size to use
            if (blockSize != null)
                if (algo.BlockSize != blockSize)
                    algo.BlockSize = (int)blockSize;

            // Set the plainData size
            if (keySize != null)
                if (algo.KeySize != keySize)
                    algo.KeySize = (int)keySize;
        }
    }
}
