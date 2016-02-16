using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Tests.Security.Cryptography.Hash
{
    public class Hasher<T> : IDisposable
        where T : HashAlgorithm, new()
    {
        T algo;
        bool disposeAlgorithm = true;
        Encoding encoding = Encoding.UTF8;

        public T Algorithm
        {
            get
            {
                return algo;
            }
            set
            {
                algo = value;
            }
        }
        public Encoding Encoding
        {
            get { return encoding; }
            set { encoding = value; }
        }

        // Decorator
        public int InputBlockSize
        {
            get
            {
                return algo.InputBlockSize;
            }
        }
        public int OutputBlockSize
        {
            get
            {
                return algo.OutputBlockSize;
            }
        }
        public int HashSize
        {
            get
            {
                return algo.HashSize;
            }
        }
        public byte[] AlgoHash
        {
            get
            {
                return algo.Hash;
            }
        }

        public Hasher()
        {
            algo = new T();
        }
        public Hasher(T refAlgo, bool disposeAlgorithm = false)
        {
            if (refAlgo == null)
                throw new ArgumentNullException("refAlgo");
            algo = refAlgo;
            this.disposeAlgorithm = disposeAlgorithm;
        }

        public byte[] Hash(Stream dataStream)
        {
            return algo.ComputeHash(dataStream);
        }
        public byte[] Hash(string stringToHash)
        {
            return Hash(encoding.GetBytes(stringToHash), 1);
        }
        public byte[] Hash(byte[] dataToHash)
        {
            return Hash(dataToHash, 1);
        }
        
        public byte[] Hash(byte[] dataToHash, int offSet, int length)
        {
            byte[] wannabeHash = new byte[length];
            Array.Copy(dataToHash, offSet, wannabeHash, 0, length);
            return Hash(wannabeHash, 1);
        }
        public byte[] Hash(byte[] dataToHash, int rounds)
        {
            if (dataToHash == null)
                throw new ArgumentNullException("dataToHash");
            if (rounds < 1)
                throw new ArgumentOutOfRangeException("rounds cannot be < 1");

            byte[] hash = algo.ComputeHash(dataToHash);

            for (int i = 1; i < rounds; i++)
                hash = algo.ComputeHash(hash);

            return hash;
        }

        public string HashToString(string stringToHash)
        {
            return HashToString(stringToHash, 1);
        }
        public string HashToString(string stringToHash, int rounds)
        {
            return HashToString(encoding.GetBytes(stringToHash), rounds);
        }
        public string HashToString(byte[] dataToHash)
        {
            return HashToString(dataToHash, 1);
        }
        public string HashToString(byte[] dataToHash, int rounds)
        {
            return Convert.ToBase64String(Hash(dataToHash, rounds));
        }

        ~Hasher()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool isDisposing)
        {
            if(isDisposing)
            {
                if(disposeAlgorithm)
                    algo.Dispose();
                algo = null;
            }
        }
    }
}
