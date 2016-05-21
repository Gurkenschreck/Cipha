using Cipha.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipha.Security.Cryptography.Symmetric;
using System.Security.Cryptography;
using System.IO;

namespace Cipha.Security.IO
{
    /// <summary>
    /// The CipherStream is mostly used in combination
    /// with a SymmetricCipher.
    /// </summary>
    /// <typeparam name="T">The symmetric algorithm which is used inside the SymmetricCipher.</typeparam>
    public class CipherStream<T> : IDisposable
        where T : SymmetricAlgorithm, new()
    {
        protected SymmetricCipher<T> cipher;
        protected int bufferLength;

        /// <summary>
        /// The BufferLength describes how many bytes
        /// should be written at once in the encryption
        /// process.
        /// </summary>
        public int BufferLength
        {
            get { return bufferLength; }
            set { bufferLength = value; }
        }

        /// <summary>
        /// Gets the instance of the symmetricCipher
        /// in use.
        /// </summary>
        public SymmetricCipher<T> Cipher
        {
            get { return cipher; }
        }

        /// <summary>
        /// Creates a new instance of the CipherStream.
        /// 
        /// Acceps the symmetricCipher which shall be used in the
        /// encryption process.
        /// </summary>
        /// <param name="symmetricCipher">The symmetricCipher instance to use.</param>
        public CipherStream(SymmetricCipher<T> cipher)
            : this(cipher, 100)
        {        }

        /// <summary>
        /// Creates a new instance of the CipherStream and 
        /// accepts a SymmetricCipher instance and the length 
        /// of the buffer used in the encryption processes.
        /// </summary>
        /// <param name="symmetricCipher">The valid SymmetricCipher instance.</param>
        /// <param name="bufferLength">The amount of bytes which shall be encrypted at once.</param>
        public CipherStream(SymmetricCipher<T> cipher, int bufferLength)
        {
            if(cipher == null)
                throw new ArgumentNullException("symmetricCipher");
            if (bufferLength <= 0)
                throw new ArgumentOutOfRangeException("bufferLength cannot be less or equal 0");

            this.cipher = cipher;
            this.bufferLength = bufferLength;
        }

        /// <summary>
        /// Encrypts an arbitrary stream and writes the 
        /// data to another stream.
        /// 
        /// Throws
        ///     CryptographicException
        /// </summary>
        /// <param name="source">The source stream to read from.</param>
        /// <param name="writeTo">The destination stream to write the encrypted data to.</param>
        public void EncryptStream(Stream source, Stream writeTo)
        {
            //Create variables to help with read and write.
            byte[] bin = new byte[bufferLength];
            long rdlen = 0;         
            long totlen = source.Length;   
            int len;                   

            using(CryptoStream encStream = new CryptoStream(writeTo, cipher.Algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                try
                {
                    while (rdlen < totlen)
                    {
                        len = source.Read(bin, 0, bufferLength);
                        encStream.Write(bin, 0, len);
                        rdlen = rdlen + len;
                    }
                }
                catch(CryptographicException ex)
                {
                    throw new CryptographicException("encryption failed most likely due to wrong configuration", ex);
                }
            }

            Utilities.SetArrayValuesZero(bin);
            rdlen = 0;
            totlen = 0;
            len = 0;
        }

        /// <summary>
        /// Decrypts an arbitrary stream using the
        /// current crypto configuration.
        /// 
        /// Throws
        ///     CryptographicException
        /// </summary>
        /// <param name="source"></param>
        /// <param name="writeTo"></param>
        public void DecryptStream(Stream source, Stream writeTo)
        {
            //Create variables to help with read and write.
            long totlen = source.Length;    //This is the total length of the input file.

            using (CryptoStream decStream = new CryptoStream(source, cipher.Algorithm.CreateDecryptor(), CryptoStreamMode.Read))
            {
                // read byte for byte
                int bytee = 0;
                try
                {
                    while (((bytee = decStream.ReadByte()) != -1))
                    {
                        writeTo.WriteByte((byte)bytee);
                    }
                }
                catch(CryptographicException ex)
                {
                    throw new CryptographicException("decryption failed most likely due to wrong configuration", ex);
                }
            }

            totlen = 0;
        }

        /// <summary>
        /// Helper method to encrypt a file.
        /// 
        /// Throws
        ///     CryptographicException
        /// </summary>
        /// <param name="inFile">The file to encrypt.</param>
        /// <param name="outFile">The encrypted inFile.</param>
        public void EncryptFile(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using (FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                using (FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    EncryptStream(fIn, fOut);
                }
            }
        }

        /// <summary>
        /// Helper method to decrypt a file.
        /// 
        /// Throws
        ///     CryptographicException
        /// </summary>
        /// <param name="inFile">The file to decrypt.</param>
        /// <param name="outFile">The decrypted inFile.</param>
        public void DecryptFile(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using (FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                using (FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    DecryptStream(fIn, fOut);
                }
            }
        }

        /// <summary>
        /// Destructor called by the DC.
        /// </summary>
        ~CipherStream()
        {
            Dispose(false);
        }

        /// <summary>
        /// Method to release all ressources of the CipherStream.
        /// 
        /// Warning: The symmetricCipher itself will not be cleared.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose with an indicator if the Dispose call was
        /// made by the client or the GC.
        /// </summary>
        /// <param name="disposing">If the object is disposed by the client.</param>
        protected void Dispose(bool disposing)
        {
            if(disposing)
            {
                bufferLength = 0;
            }
        }
    }
}
