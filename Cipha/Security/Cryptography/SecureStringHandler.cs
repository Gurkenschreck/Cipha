using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    /// <summary>
    /// SecureString decorator.
    /// See: Decorator structural pattern.
    /// </summary>
    class SecureStringHandler : IDisposable
    {
        bool disposed = false;
        SecureString secStr;

        public SecureStringHandler()
        {
            secStr = new SecureString();
        }

        /// <summary>
        /// Called by GC.
        /// You cannot be sure if the managed ressources
        /// are still there.
        /// </summary>
        ~SecureStringHandler()
        {
            Dispose(false);
        }

        /// <summary>
        /// Disposed is called directly by the client.
        /// So you can release all managed ressources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        public void Dispose(bool isDisposing)
        {
            if(!disposed)
            {
                if (isDisposing)
                {
                    if (secStr != null)
                    {
                        secStr.Dispose();
                        secStr = null;
                    }
                }
            }
        }

        public int Length { get { return secStr.Length; } }

        public void AppendChar(char c)
        {
            secStr.AppendChar(c);
        }

        public void Clear() { secStr.Clear(); }
        public SecureString Copy() { return secStr.Copy(); }
        public void InsertAt(int index, char c) { secStr.InsertAt(index, c); }
        public bool IsReadOnly() { return secStr.IsReadOnly(); }
        public void MakeReadOnly() { secStr.MakeReadOnly(); }
        public void RemoveAt(int index) { secStr.RemoveAt(index); }
        public void SetAt(int index, char c) { secStr.SetAt(index, c); }

        public void ApplyString(string str)
        {
            secStr.Clear();
            AppendString(str);
        }
        public void ApplyString(SecureString str)
        {
            secStr.Clear();
            secStr = str.Copy();
        }
        public void AppendString(string str)
        {
            foreach (char c in str)
                secStr.AppendChar(c);
        }
    }
}
