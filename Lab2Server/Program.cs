using System;

namespace Lab2Server
{
    class Program
    {
        static void Main(string[] args)
        {
            Server.RegisterUser("UserA", "11111");
            Server.RegisterUser("UserB", "22222");
            Server.StartListening();
        }
    }
}
