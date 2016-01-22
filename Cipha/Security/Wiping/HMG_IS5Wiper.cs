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
                    long maximumValue = 0;
                    int divisor = 50;
                    int maxRounds = (Enhanced) ? 3 : 1;


                    for(int round = 0; round < maxRounds; round ++)
                    {
                        bytes = Enumerable.Repeat<byte>(0x00, (int)fs.Length / divisor).ToArray();
                        maximumValue = fs.Length - bytes.Length;
                        while (fs.Position < maximumValue)
                            fs.Write(bytes, 0, bytes.Length);
                        while (fs.Position < maximumValue)
                            fs.WriteByte(0x00);


                        bytes = Enumerable.Repeat<byte>(0xFF, (int)fs.Length / 50).ToArray();
                        while (fs.Position < maximumValue)
                            fs.Write(bytes, 0, bytes.Length);
                        while (fs.Position < maximumValue)
                            fs.WriteByte(0x00);

                        rdm.NextBytes(bytes);
                        while (fs.Position < maximumValue)
                            fs.Write(bytes, 0, bytes.Length);
                        while (fs.Position < maximumValue)
                            fs.WriteByte(0x00);
                    }
                    
                }
                File.Delete(filePath);
            }
            return true;
        }
    }
}
