using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CiphaConsole
{
    public class INIFileReader
    {
        string iniFile;
        public string INIFile{get;set;}

        Dictionary<string, string> properties;
        public Dictionary<string, string> Properties
        {
            get { return properties; }
            set { properties = value; }
        }

        public INIFileReader(string iniFile)
        {
            if(File.Exists(iniFile))
            {
                this.iniFile = iniFile;
                string[] lines = File.ReadAllLines(iniFile);

                foreach(string line in lines)
                {
                    string key = line.Split('=')[0];
                    string value = line.Split('=')[1];

                    properties.Add(key, value);
                }
            }
        }

        public void Save()
        {
            using(StreamWriter sw = new StreamWriter(iniFile))
            {
                try
                {
                    foreach (var pair in properties)
                    {
                        sw.WriteLine(String.Format("{0}={1}", pair.Key, pair.Value));
                    }
                }
                finally
                {
                    sw.Flush();
                    sw.Close();
                }
                
            }
        }
    }
}
