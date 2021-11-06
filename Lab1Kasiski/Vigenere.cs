namespace Kasiski
{
    class Vigenere
    {
        public string defaultAlphabet { get; set; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        private string GetRepeatKey(string s, int n)
        {
            string p = s;
            while (p.Length < n)
            {
                p += p;
            }

            return p.Substring(0, n);
        }

        private string VigenereEncryption(string text, string password, string alphabet, bool encrypting = true)
        {
            string gamma = GetRepeatKey(password, text.Length);
            string retValue = "";

            for (int i = 0; i < text.Length; i++)
            {
                int letterIndex = alphabet.IndexOf(text[i]);
                int codeIndex = alphabet.IndexOf(gamma[i]);
                if (letterIndex < 0)
                {
                    retValue += text[i].ToString();
                }
                else
                {
                    retValue += alphabet[(alphabet.Length + letterIndex + ((encrypting ? 1 : -1) * codeIndex)) % alphabet.Length].ToString();
                }
            }

            return retValue;
        }

        public string Encrypt(string plainMessage, string password)
        {
            return VigenereEncryption(plainMessage, password, defaultAlphabet);
        }

        public string Decrypt(string encryptedMessage, string password)
        {
            return VigenereEncryption(encryptedMessage, password, defaultAlphabet, false);
        }
    }
}
