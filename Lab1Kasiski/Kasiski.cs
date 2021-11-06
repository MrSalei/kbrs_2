using System;
using System.Collections.Generic;
using System.Linq;

namespace Kasiski
{
    class Kasiski
    {
        public string DefaultAlphabet { get; set; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public Dictionary<char, double> DefaultAlphabetFrequencies { get; set; } = new Dictionary<char, double>()
        {
            ['A'] = 0.08167,
            ['B'] = 0.01492,
            ['C'] = 0.02782,
            ['D'] = 0.04253,
            ['E'] = 0.12702,
            ['F'] = 0.0228,
            ['G'] = 0.02015,
            ['H'] = 0.06094,
            ['I'] = 0.06966,
            ['J'] = 0.00153,
            ['K'] = 0.00772,
            ['L'] = 0.04025,
            ['M'] = 0.02406,
            ['N'] = 0.06749,
            ['O'] = 0.07507,
            ['P'] = 0.01929,
            ['Q'] = 0.00095,
            ['R'] = 0.05987,
            ['S'] = 0.06327,
            ['T'] = 0.09056,
            ['U'] = 0.02758,
            ['V'] = 0.00978,
            ['W'] = 0.0236,
            ['X'] = 0.0015,
            ['Y'] = 0.01974,
            ['Z'] = 0.00074
        };
        private int Gcd(int a, int b)
        {
            if (b == 0)
                return a;
            else
                return Gcd(b, a % b);

        }

        private int GcdForArray(int[] list)
        {
            int left, right;
            if (list.Length > 2)
            {
                left = GcdForArray(list[..(list.Length / 2)]);
                right = GcdForArray(list[(list.Length / 2)..]);
            }
            else
            {
                if (list.Length == 1)
                {
                    return list[0];
                }
                else
                {
                    left = list[0];
                    right = list[1];
                }
            }

            return Gcd(left, right);
        }

        public int GetMostFrequentDistances(string text, int diagramLength = 3)
        {
            SortedDictionary<int, int> repeatCount = new SortedDictionary<int, int>();
            int totalCounter = 0;
            for (int i = 0; i < text.Length - diagramLength + 1; i++)
            {
                string temp = text.Substring(i, diagramLength);
                for (int j = i + diagramLength; j < text.Length - diagramLength + 1; j++)
                {
                    string temp2 = text.Substring(j, diagramLength);
                    if (temp.Equals(temp2))
                    {
                        int diff = j - i;

                        if (diff > 500)
                        {
                            continue;
                        }

                        totalCounter++;
                        if (!repeatCount.ContainsKey(diff))
                        {
                            repeatCount.Add(diff, 1);
                        }
                        else
                        {
                            repeatCount[diff]++;
                        }
                    }
                }
            }

            List<int> mostFreq = new List<int>();
            foreach (KeyValuePair<int, int> pair in repeatCount)
            {
                if ((double)pair.Value / (double)totalCounter > 0.01)
                {
                    mostFreq.Add(pair.Key);
                }
            }

            return GcdForArray(mostFreq.ToArray());
        }

        private int СalculateFrequencyDifference(Dictionary<char, double> customFrequincies)
        {
            var dF = DefaultAlphabetFrequencies.Values.ToArray();
            var dC = customFrequincies.Values.ToArray();
            List<double> difference = new List<double>();
            for (int i = 0; i < DefaultAlphabet.Length; i++)
            {
                double totalDifference = 0;
                for (int j = 0; j < dF.Length; j++)
                {
                    totalDifference += Math.Abs(dF[j] - dC[(j + i) % customFrequincies.Count]);
                }

                difference.Add(totalDifference);
            }

            return difference.IndexOf(difference.Min());
        }
        public string RestoreKey(string text, int keyLength)
        {
            string[] caeserStrings = GetCaesarStrings(text, keyLength);
            string key = "";

            for (int i = 0; i < caeserStrings.Length; i++)
            {
                var freq = GetFreq(caeserStrings[i]);
                int mov = СalculateFrequencyDifference(freq);
                key += DefaultAlphabet[mov];
            }

            return key;
        }
        public string[] GetCaesarStrings(string encryptedText, int keyLength)
        {
            string[] encryptedCaeserStrings = new string[keyLength];
            for (int i = 0; i < encryptedText.Length - keyLength; i += keyLength)
            {
                for (int j = 0; j < keyLength; j++)
                {
                    encryptedCaeserStrings[j] += encryptedText[i + j];
                }
            }

            return encryptedCaeserStrings;
        }

        public Dictionary<char, double> GetFreq(string encryptedCaesarString)
        {
            Dictionary<char, int> charCounters = new Dictionary<char, int>();
            foreach (char c in DefaultAlphabet)
            {
                charCounters.Add(c, 0);
            }

            Dictionary<char, double> charFrequincies = new Dictionary<char, double>();

            for (int i = 0; i < encryptedCaesarString.Length; i++)
            {
                char currentSymbol = encryptedCaesarString[i];
                if (DefaultAlphabet.Contains(currentSymbol))
                {
                    charCounters[currentSymbol]++;
                }
            }

            foreach (KeyValuePair<char, int> pair in charCounters)
            {
                charFrequincies.Add(pair.Key, (double)pair.Value / (double)encryptedCaesarString.Length);
            }

            return charFrequincies;
        }
    }
}
