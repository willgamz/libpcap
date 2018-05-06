using System;
using System.Threading;

namespace libpcap_cmd
{
    using pcap;    

    class Program
    {
        static void Main(string[] args)
        {
            string ifname = @"\Device\NPF_{64ABBD61-F073-4514-8027-A228B53C57CE}";
            string ifname2 = @"\Device\NPF_{C2BD39CA-A1ED-4D54-BD72-46C983272385}";

            //pcap_if.dumpalldevs(Console.Out);
            //loop_dump_pkts(ifname);
            byte[] data = new byte[]
               {
                0xe8,0x94,0xf6,0x93,0xff,0x4a,0x10,0xc3,0x7b,0x93,0x87,0xd0,0x08,0x00,0x45,0x00,
0x00,0x34,0x64,0xa9,0x40,0x00,0x80,0x06,0x3c,0xc1,0xac,0x10,0x00,0x06,0xac,0xd9,
0x00,0x6a,0x2c,0x40,0x01,0xbb,0x18,0xe0,0x16,0x46,0x00,0x00,0x00,0x00,0x80,0x02,
0xfa,0xf0,0xbd,0xa4,0x00,0x00,0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x08,0x01,0x01,
0x04,0x02
           };

            send(ifname, data);
        }

        static void send(string ifname, byte[] data)
        {
            var ifpc = get_if(ifname);

            if (ifpc == null)
                return;           

            ifpc.open_if_live();

            ifpc.send_packet(data);

            ifpc.close_if();
        }

        static void loop_dump_pkts(string ifname, int secs = 10)
        {
            var ifpc = get_if(ifname);

            if (ifpc == null)
                return;

            try
            {
                Thread cap = new Thread(capture_loop);
                cap.Start(ifpc);

                int count = 0;
                while (true)
                {
                    count++;
                    if (count > secs)
                        break;

                    Thread.Sleep(1000);
                }
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                ifpc.pcap_breakloop();
                ifpc.close_if();
            }
        }

        static pcap_if get_if(string ifname)
        {
            var allif = pcap.pcap_if.findalldevs();
            pcap_if.dumpalldevs(Console.Out);

            pcap_if ifpc = null;

            foreach (var it in allif)
            {
                if (it.name.Equals(ifname))
                {
                    ifpc = it;
                    break;
                }
            }

            return ifpc;
        }

        static void pcap_pkt_handler(pcap_pktdata pkt)
        {
            var dp = new utils.BinaryView();
            Console.WriteLine(dp.GenerateText(pkt.payload));
        }

        static void capture_loop(object data)
        {
            var ifpc = (pcap_if)data;
            ifpc.open_if_live();
            ifpc.loop_capture(pcap_pkt_handler);            
        }
    }
}
