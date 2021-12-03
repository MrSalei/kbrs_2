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
        private static ECDiffieHellmanOpenSsl _serverKey = new ECDiffieHellmanOpenSsl(ECCurve.NamedCurves.nistP521);
        public static void StartListening()
        {
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
                if (content.IndexOf("<EOF>") > -1)
                { 
                    ParseRequest(state.bytesCollector.ToArray()[..(content.IndexOf("<EOF>") + 5)], state);
                }
                else
                {
                    Console.WriteLine("Keep reading.");
                    handler.BeginReceive(state.buffer, 0, StateObject.BufferSize, 0,
                    new AsyncCallback(ReadCallback), state);
                }
            }
        }

        public static void RegisterUser(string username, string password)
        {
            _clients.Add(username, password);
        }

        private static void ParseRequest(byte[] request, StateObject state)
        {
            string option = Encoding.ASCII.GetString(request[..5]);

            byte[] response;
            Console.WriteLine($"{option}");
            switch (option)
            {
                case "<SET>":
                    response = CreateSetResponse(ref state, request);
                    break;
                case "<DIR>":
                    response = CreateDirResponse(ref state, request);
                    break;
                case "<GET>":
                    response = CreateGetResponse(ref state, request);
                    break;
                case "<NEW>":
                    response = CreateNewResponse(ref state, request);
                    break;
                case "<MOD>":
                    response = CreateNewResponse(ref state, request);
                    break;
                case "<DEL>":
                    response = CreateDelResponse(ref state, request);
                    break;
                default:
                    response = CreateErrResponse(ref state, "No such option");
                    break;
            }

            Console.WriteLine($"sooqa: {DateTime.Now.Ticks.ToString()} {state.sessionKey is null}");
            Send(state, response);
        }

        private static byte[] CreateErrResponse(ref StateObject state, string msg)
        {
            List<byte> bytes = new List<byte>();
            byte[] bMsg = Encoding.ASCII.GetBytes(msg);
            bytes.AddRange(Encoding.ASCII.GetBytes("<ERR>"));
            bytes.AddRange(BitConverter.GetBytes(bMsg.Length));
            bytes.AddRange(bMsg);
            return bytes.ToArray();
        }

        private static byte[] CreateSetResponse(ref StateObject state, byte[] request)
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
                return CreateErrResponse(ref state, "Not registered");
            }

            if (!_clients[login].Equals(password))
            {
                return CreateErrResponse(ref state, "Wrong password");
            }

            Random rng = new Random((int)DateTime.Now.Ticks);
            List<byte> bytes = new List<byte>();
            state.key.ImportSubjectPublicKeyInfo(request[offset..^5], out _);
            state.sessionKey = _serverKey.DeriveKeyMaterial(state.key.PublicKey);

            byte[] serverKeyPublic = _serverKey.ExportSubjectPublicKeyInfo();
            int size = 4 + serverKeyPublic.Length;
            bytes.AddRange(Encoding.ASCII.GetBytes("<KEY>"));
            bytes.AddRange(BitConverter.GetBytes(size));
            bytes.AddRange(serverKeyPublic);
            state.validTo = new DateTime(DateTime.Now.AddMinutes(5).Ticks);
            return bytes.ToArray();
        }

        private static byte[] CreateDirResponse(ref StateObject state, byte[] request)
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

        private static byte[] CreateGetResponse(ref StateObject state, byte[] request)
        {
            if (state.validTo.Ticks < DateTime.Now.Ticks)
            {
                return CreateErrResponse(ref state, "KEY EXPIRED");
            }

            int fileLength = BitConverter.ToInt32(request[5..9]);
            string fileName = Encoding.ASCII.GetString(request[9..(9 + fileLength)]);
            string msg = File.ReadAllText($"./files/{fileName}");
            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<TXT>"));
            bytes.AddRange(CryptoHelp.GetEncryptedMessage(state.sessionKey, msg));
            return bytes.ToArray();
        }

        private static byte[] CreateNewResponse(ref StateObject state, byte[] request)
        {
            if (state.validTo.Ticks < DateTime.Now.Ticks)
            {
                return CreateErrResponse(ref state, "KEY EXPIRED");
            }

            int fileLength = BitConverter.ToInt32(request[5..9]);
            string fileName = Encoding.ASCII.GetString(request[9..(9 + fileLength)]);
            string decMsg = CryptoHelp.GetDecryptedMessage(state.sessionKey, request[(9 + fileLength + 4)..^5]);
            File.WriteAllText($"./files/{fileName}", decMsg);
            byte[] msg = Encoding.ASCII.GetBytes("Request successful");

            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<SUC>"));
            bytes.AddRange(BitConverter.GetBytes(4 + msg.Length));
            bytes.AddRange(msg);
            return bytes.ToArray();
        }

        private static byte[] CreateDelResponse(ref StateObject state, byte[] request)
        {
            if (state.validTo.Ticks < DateTime.Now.Ticks)
            {
                return CreateErrResponse(ref state, "KEY EXPIRED");
            }

            string fileName = Encoding.ASCII.GetString(request[5..^5]);
            Console.WriteLine(fileName);
            Console.WriteLine(request.Length);
            File.Delete($"./files/{fileName}");

            byte[] msg = Encoding.ASCII.GetBytes("Request successful");

            List<byte> bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("<SUC>"));
            bytes.AddRange(BitConverter.GetBytes(4 + msg.Length));
            bytes.AddRange(msg);
            return bytes.ToArray();
        }

        private static void Send(StateObject state, byte[] data)
        {
            Console.WriteLine($"Sending {Encoding.ASCII.GetString(data)}");
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
                newState.sessionKey = new byte[32];
                Console.WriteLine($"in the end {oldState.sessionKey is null}");
                oldState.sessionKey.CopyTo(newState.sessionKey, 0);
                newState.validTo = new DateTime(oldState.validTo.Ticks);

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

            public ECDiffieHellmanOpenSsl key = new ECDiffieHellmanOpenSsl(ECCurve.NamedCurves.nistP521);

            public byte[] sessionKey;

            public DateTime validTo;

            public List<byte> bytesCollector = new List<byte>();

            public Socket workSocket = null;
        }
    }
}
