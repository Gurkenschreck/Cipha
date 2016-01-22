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
    public class CryptoFileHandler<T> : IDisposable
        where T : SymmetricAlgorithm, new()
    {
        SymmetricCipher<T> cipher;
        int bufferLength;

        public int BufferLength
        {
            get { return bufferLength; }
            set { bufferLength = value; }
        }

        public SymmetricCipher<T> Cipher
        {
            get { return cipher; }
        }

        public CryptoFileHandler(SymmetricCipher<T> cipher)
            : this(cipher, 100)
        {        }

        public CryptoFileHandler(SymmetricCipher<T> cipher, int bufferLength)
        {
            if(cipher == null)
                throw new ArgumentNullException("cipher");
            if (bufferLength <= 0)
                throw new ArgumentOutOfRangeException("bufferLength cannot be less or equal 0");

            this.cipher = cipher;
            this.bufferLength = bufferLength;
        }

        public void EncryptFile(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using (FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                //Create variables to help with read and write.
                byte[] bin = new byte[bufferLength]; //This is intermediate storage for the encryption.
                long rdlen = 0;              //This is the total number of bytes written.
                long totlen = fIn.Length;    //This is the total length of the input file.
                int len;                    //This is the number of bytes to be written at a time.

                using (FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    using (CryptoStream encStream = new CryptoStream(fOut, cipher.Algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        while (rdlen < totlen)
                        {
                            len = fIn.Read(bin, 0, bufferLength);
                            encStream.Write(bin, 0, len);
                            rdlen = rdlen + len;
                        }
                    }
                }

                Utilities.SetArrayValuesZero(bin);
                rdlen = 0;
                totlen = 0;
                len = 0;
            }
        }

        public void DecryptFile(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
                throw new FileNotFoundException("inFile not found: " + inFile);

            using (FileStream fIn = new FileStream(inFile, FileMode.Open, FileAccess.Read))
            {
                //Create variables to help with read and write.
                byte[] bin = new byte[bufferLength]; //This is intermediate storage for the encryption.
                long totlen = fIn.Length;    //This is the total length of the input file.


                using (FileStream fOut = new FileStream(outFile, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    using (CryptoStream decStream = new CryptoStream(fIn, cipher.Algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        // read byte for byte
                        int bytee = 0;
                        while (((bytee = decStream.ReadByte()) != -1))
                        {
                            fOut.WriteByte((byte)bytee);
                        }
                    }
                }

                Utilities.SetArrayValuesZero(bin);
                totlen = 0;
            }
        }

        ~CryptoFileHandler()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected void Dispose(bool disposing)
        {
            if(disposing)
            {
                bufferLength = 0;
            }
        }
    }
}
