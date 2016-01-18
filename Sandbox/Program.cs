using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipha.Security.Cryptography.Symmetric;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Threading;
namespace Sandbox
{
    class Program
    {
        static void Main(string[] args)
        {
            GenericSymmetricCipher<TripleDESCryptoServiceProvider> cipher = new GenericSymmetricCipher<TripleDESCryptoServiceProvider>();

            byte[] key = null, iv = null;

            cipher.EncryptFile("1967.rar", "encrypted.rar", ref key, ref iv);

            cipher.DecryptFile("encrypted.rar", "1111.rar", key, iv);

            Console.WriteLine("fin");
            Console.ReadKey(true);
        }
        public static void Flush()
        {
            List<MemoryStream> streams = new List<MemoryStream>(1000);
            MemoryStream ms = null;
            for (int i = 0; i < 150; i++)
            {
                try
                {
                    ms = new MemoryStream();
                    bool d = true;
                    while (d)
                    {
                        ms.WriteByte(0x00);
                    }
                }
                catch (OutOfMemoryException) { }
                finally
                {
                    ms.Close();
                    streams.Add(ms);
                    Console.WriteLine(i);
                }
            }

            foreach (MemoryStream m in streams)
            {
                m.Dispose();
            }
            streams.Clear();
            streams = null;
        }
    }
}
