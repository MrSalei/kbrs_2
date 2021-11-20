using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Lab2Server
{
    class Server
    {
        public static ManualResetEvent allDone = new ManualResetEvent(false);
        private static List<Socket> _socketsList = new List<Socket>();
        private static Dictionary<string, string> _clients = new Dictionary<string, string>();
        public static void StartListening()
        {
            _clients.Add("user", "password");
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

            Socket listener = new Socket(ipAddress.AddressFamily,
                SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(100);

                while (true)
                {
                    allDone.Reset();
 
                    Console.WriteLine("Waiting for a connection...");
                    listener.BeginAccept(
                        new AsyncCallback(AcceptCallback),
                        listener);

                    allDone.WaitOne();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            Console.WriteLine("\nPress ENTER to continue...");
            Console.Read();
        }

        public static void AcceptCallback(IAsyncResult ar)
        {
            allDone.Set();
 
            Socket listener = (Socket)ar.AsyncState;
            Socket handler = listener.EndAccept(ar);

            StateObject state = new StateObject();
            state.workSocket = handler;
            handler.BeginReceive(state.buffer, 0, StateObject.BufferSize, 0,
                new AsyncCallback(ReadCallback), state);
        }

        public static void ReadCallback(IAsyncResult ar)
        {
            string content = string.Empty;
 
            StateObject state = (StateObject)ar.AsyncState;
            Socket handler = state.workSocket;

            int bytesRead = handler.EndReceive(ar);

            if (bytesRead > 0)
            {
                state.bytesCollector.AddRange(state.buffer);
                content = Encoding.ASCII.GetString(state.bytesCollector.ToArray());
                Console.WriteLine(content);
                if (content.IndexOf("<EOF>") > -1)
                { 
                    ParseRequest(state.bytesCollector.ToArray(), ref state);
                }
                else
                {
                    Console.WriteLine("Keep reading.");
                    handler.BeginReceive(state.buffer, 0, StateObject.BufferSize, 0,
                    new AsyncCallback(ReadCallback), state);
                }
            }
        }

        private static void ParseRequest(byte[] request, ref StateObject state)
        {
            string option = Encoding.ASCII.GetString(request[..5]);
            if (state.validTo.Ticks < DateTime.Now.Ticks)
            {
                Send(state, CreateErrResponse(state, "KEY EXPIRED"));
            }

            switch (option)
            {
                case "<SET>":
                    Send(state, CreateSetResponse(state, request));
                    break;
                case "<DIR>":
                    Send(state, CreateDirResponse(state, request));
                    break;
                case "<GET>":
                    Send(state, CreateGetResponse(state, request));
                    break;
                case "<NEW>":
                    Send(state, CreateNewResponse(state, request));
                    break;
                case "<MOD>":
                    Send(state, CreateNewResponse(state, request));
                    break;
                case "<DEL>":
                    Send(state, CreateDelResponse(state, request));
                    break;
                default:
                    break;
            }
        }

        private static byte[] CreateErrResponse(StateObject state, string msg)
        {
            List<byte> bytes = new List<byte>();
            byte[] bMsg = Encoding.ASCII.GetBytes(msg);
            bytes.AddRange(Encoding.ASCII.GetBytes("<ERR>"));
            bytes.AddRange(BitConverter.GetBytes(bMsg.Length));
            bytes.AddRange(bMsg);
            return bytes.ToArray();
        }

        private static byte[] CreateSetResponse(StateObject state, byte[] request)
        {
            int offset = 5;
            int loginSize = BitConverter.ToInt32(request[offset..(offset + 4)]);
            offset += 4;
            string login = Encoding.ASCII.GetString(request[offset..(offset + loginSize)]);
            offset += loginSize;
            int passwordSize = BitConverter.ToInt32(request[offset..(offset + 4)]);
            offset += 4;
            string password = Encoding.ASCII.GetString(request[offset..(offset + passwordSize)]);
            offset += passwordSize;

            if (!_clients.ContainsKey(login))
            {
                return CreateErrResponse(state, "Not registered");
            }

            if (!_clients[login].Equals(password))
            {
                return CreateErrResponse(state, "Wrong password");
            }

            Random rng = new Random((int)DateTime.Now.Ticks);
            List<byte> bytes = new List<byte>();
            state.key.ImportECPrivateKey(request[5..^5], out _);
            state.sessionKey = new byte[32];
            rng.NextBytes(state.sessionKey);
            byte[] signature = state.key.SignData(state.sessionKey, HashAlgorithmName.SHA256);
            int size = 4 + 4 + state.sessionKey.Length + signature.Length;
            bytes.AddRange(Encoding.ASCII.GetBytes("<KEY>"));
            bytes.AddRange(BitConverter.GetBytes(size));
            bytes.AddRange(BitConverter.GetBytes(state.sessionKey.Length));
            bytes.AddRange(state.sessionKey);
            bytes.AddRange(signature);
            state.validTo = DateTime.Now;
            state.validTo.AddMinutes(5);
            return bytes.ToArray();
        }

        private static byte[] CreateDirResponse(StateObject state, byte[] request)
        {
            List<byte> bytes = new List<byte>();
            string[] files = Directory.GetFiles("./files/");
            StringBuilder fileDirectoryBuilder = new StringBuilder();
            foreach (string file in files)
            {
                fileDirectoryBuilder.Append(file);
                fileDirectoryBuilder.Append("\n");
            }
            int size = 4 + fileDirectoryBuilder.ToString().Length;
            bytes.AddRange(Encoding.ASCII.GetBytes("<DIR>"));
            bytes.AddRange(BitConverter.GetBytes(size));
            bytes.AddRange(Encoding.ASCII.GetBytes(fileDirectoryBuilder.ToString()));
            return bytes.ToArray();
        }

        private static byte[] CreateGetResponse(StateObject state, byte[] request)
        {
            int fileLength = BitConverter.ToInt32(request[5..9]);
            string fileName = Encoding.ASCII.GetString(request[9..(9 + fileLength)]);
            string msg = File.ReadAllText($"./files/{fileName}");
            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<TXT>"));
            bytes.AddRange(CryptoHelp.GetEncryptedMessage(state.sessionKey, msg));
            return bytes.ToArray();
        }

        private static byte[] CreateNewResponse(StateObject state, byte[] request)
        {
            int fileLength = BitConverter.ToInt32(request[5..9]);
            string fileName = Encoding.ASCII.GetString(request[9..(9 + fileLength)]);
            string decMsg = CryptoHelp.GetDecryptedMessage(state.sessionKey, request[(9 + fileLength)..^5]);
            File.Create($"./files/{fileName}");
            File.WriteAllText($"./files/{fileName}", decMsg);

            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<SUC>"));
            bytes.AddRange(BitConverter.GetBytes(9));
            return bytes.ToArray();
        }

        private static byte[] CreateDelResponse(StateObject state, byte[] request)
        {
            string fileName = Encoding.ASCII.GetString(request[5..^5]);
            File.Delete($"./files/{fileName}");

            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<SUC>"));
            bytes.AddRange(BitConverter.GetBytes(9));
            return bytes.ToArray();
        }

        private static void Send(StateObject state, byte[] data)
        {
            state.workSocket.BeginSend(data, 0, data.Length, 0,
                new AsyncCallback(SendCallback), state);
        }

        private static void SendCallback(IAsyncResult ar)
        {
            try
            {
                StateObject oldState = (StateObject)ar.AsyncState;
                StateObject newState = new StateObject();
                newState.workSocket = oldState.workSocket;
                newState.sessionKey = oldState.sessionKey;

                int bytesSent = newState.workSocket.EndSend(ar);
                Console.WriteLine("Sent {0} bytes to client.", bytesSent);

                newState.workSocket.BeginReceive(newState.buffer, 0, StateObject.BufferSize, 0,
                new AsyncCallback(ReadCallback), newState);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        public class StateObject
        {
            public const int BufferSize = 1024;

            public byte[] buffer = new byte[BufferSize];

            public ECDsa key = ECDsa.Create();

            public byte[] sessionKey;

            public DateTime validTo;

            public List<byte> bytesCollector = new List<byte>();

            public Socket workSocket = null;
        }
    }
}
