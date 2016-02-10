using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Wiping
{
    public abstract class Wiper
    {
        public abstract void WipeFile(string filePath);
        public abstract void WipeStream(Stream stream);
    }
}
