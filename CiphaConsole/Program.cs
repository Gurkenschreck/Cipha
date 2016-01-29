using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipha;
using Cipha.Security.Wiping;
using Cipha.Security.Cryptography;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using Cipha.Security.Cryptography.Symmetric;

namespace CiphaConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                string choice = "";
                string mainCmd = "";
                do
                {
                    Console.Write("$Cipha: ");
                    choice = Console.ReadLine();
                    string[] cmds = choice.Split(' ');
                    mainCmd = choice.Contains(" ") ? choice.Substring(0, choice.IndexOf(' ')) : choice;

                    switch (mainCmd)
                    {
                        case "lst":
                            string path = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
                            Console.WriteLine(path);
                            break;
                        case "enc":
                            if (cmds.Length != 4)
                            {
                                Console.WriteLine("Insufficient parameters for 'dec'. Use: dec <plainFile> <encryptedFile> <password>");
                                return;
                            }
                            string from = cmds[1];
                            string to = cmds[2];
                            string pw = cmds[3];

                            if (File.Exists(from))
                            {
                                File.WriteAllBytes(to, new GenericSymmetricCipher<RijndaelManaged>().Encrypt(File.ReadAllBytes(from), pw, "abcdefghij;;;"));
                            }

                            break;
                        case "dec":
                            if (cmds.Length != 4)
                            {
                                Console.WriteLine("Insufficient parameters for 'dec'. Use: dec <encryptedFile> <normalFile> <password>");
                                return;
                            }

                            string from2 = cmds[1];
                            string to2 = cmds[2];
                            string pw2 = cmds[3];

                            break;
                        case "rm":
                            string input = cmds[1];
                            Wiper dest = new HMG_IS5WiperFactory().CreateWiper();
                            dest.WipeFile(input);
                            break;
                        case "quit":
                        case "q":
                            break;
                        default:
                            Console.WriteLine("Command not recognized.");
                            break;
                    }
                } while (mainCmd != "q" && mainCmd != "quit");
            }
        }
    }
}
