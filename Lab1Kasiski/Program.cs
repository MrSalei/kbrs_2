using System;
using System.IO;

namespace Kasiski
{
    class Program
    {
        static void Main(string[] args)
        {
            Kasiski kasiski = new Kasiski();
            Vigenere vig = new Vigenere();

            bool preEncrypt = true;
            string text;
            string orig;
            
            Console.Write("Work mode (1/2) >");
            int choice = int.Parse(Console.ReadLine());
            switch (choice)
            {
                case 1:
                    preEncrypt = true;
                    break;
                case 2:
                    preEncrypt = false;
                    break;
                default:
                    preEncrypt = true;
                    break;
            }

            if (preEncrypt)
            {
                orig = File.ReadAllText("original.txt").ToUpperInvariant();
                Console.Write("Key >");
                string encKey = Console.ReadLine().ToUpperInvariant();
                text = vig.Encrypt(orig, encKey);
            }
            else
            {
                using (StreamReader sr = new StreamReader("original.txt"))
                {
                    orig = sr.ReadToEnd().ToUpper();
                }

                text = File.ReadAllText("encrypted.txt");
            }

            Console.WriteLine(text);

            int keyLength = kasiski.GetMostFrequentDistances(text);
            Console.WriteLine($"Assumed key length: {keyLength}");
            string key = kasiski.RestoreKey(text, keyLength);
            Console.WriteLine($"Assumed key: {key}");
            string finalText = vig.Decrypt(text, key);
            using (StreamWriter sw = new StreamWriter("hacked.txt"))
            {
                sw.Write(finalText);
            }

            Console.WriteLine("Assumed original text is in 'hacked.txt' file");
            int countGood = 0;
            int countTotal = 0;
            for (int i = 0; i < finalText.Length; i++)
            {
                char symbolOriginal = orig[i];
                char symbolMyDecrypted = finalText[i];
                if (kasiski.DefaultAlphabet.Contains(symbolOriginal))
                {
                    if (symbolOriginal == symbolMyDecrypted)
                    {
                        countGood++;
                    }
                    countTotal++;
                }
            }

            Console.WriteLine($"Encrypted text length: {text.Length}");
            Console.WriteLine($"Decrypted correctly {countGood} out of {countTotal} characters ({Math.Round((double)countGood / countTotal, 2) * 100}%)");
        }
    }
}
