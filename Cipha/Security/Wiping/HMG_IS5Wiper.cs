using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Wiping
{
    public class HMG_IS5Wiper : Wiper
    {
        public bool Enhanced { get; set; }

        public override bool WipeFile(string filePath)
        {
            if (filePath == null)
                throw new ArgumentNullException("filePath");

            if (File.Exists(filePath))
            {
                using (var fs = File.OpenWrite(filePath))
                {
                    Random rdm = new Random();
                    byte[] bytes;
                    for(int round = 0; round < 3; round ++)
                    {
                        bytes = Enumerable.Repeat<byte>(0x00, (int)fs.Length).ToArray();
                        fs.Write(bytes, 0, bytes.Length);

                        bytes = Enumerable.Repeat<byte>(0xFF, (int)fs.Length).ToArray();
                        fs.Write(bytes, 0, bytes.Length);

                        rdm.NextBytes(bytes);
                        fs.Write(bytes, 0, bytes.Length);
                    }
                    
                }
                File.Delete(filePath);
            }
            return true;
        }
    }
}
