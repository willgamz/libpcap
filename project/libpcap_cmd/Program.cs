using System;
using System.Threading;

namespace libpcap_cmd
{
    using pcap;    

    class Program
    {
        static void Main(string[] args)
        {
            loop_dump_pkts(@"\Device\NPF_{64ABBD61-F073-4514-8027-A228B53C57CE}");
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
