using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Wiping
{
    public abstract class Wiper
    {
        public abstract bool WipeFile(string filePath);
    }
}
