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

        public override void WipeFile(string filePath)
        {
            if (filePath == null)
                throw new ArgumentNullException("filePath");

            if (File.Exists(filePath))
            {
                using (var fs = File.OpenWrite(filePath))
                {
                    WipeStream(fs);
                }
                File.Delete(filePath);
            }
        }

        public override void WipeStream(Stream stream)
        {
            Random rdm = new Random();
            byte[] bytes;
            long maximumValue = 0;
            int divisor = 50;
            long steps = stream.Length / divisor;
            steps = (steps < 100) ? stream.Length : steps;

            int maxRounds = (Enhanced) ? 3 : 1;


            for (int round = 0; round < maxRounds; round++)
            {
                bytes = Enumerable.Repeat<byte>(0x00, (int)steps).ToArray();
                maximumValue = stream.Length - bytes.Length;
                while (stream.Position < maximumValue)
                    stream.Write(bytes, 0, bytes.Length);
                while (stream.Position < maximumValue)
                    stream.WriteByte(0x00);


                bytes = Enumerable.Repeat<byte>(0xFF, (int)steps).ToArray();
                while (stream.Position < maximumValue)
                    stream.Write(bytes, 0, bytes.Length);
                while (stream.Position < maximumValue)
                    stream.WriteByte(0x00);

                rdm.NextBytes(bytes);
                while (stream.Position < maximumValue)
                    stream.Write(bytes, 0, bytes.Length);
                while (stream.Position < maximumValue)
                    stream.WriteByte(0x00);
            }
            stream.SetLength(0);
        }
    }
}
