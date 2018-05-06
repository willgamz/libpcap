using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace pcap
{
    public class pcap_if
    {
        private string m_name;
        private string m_description;        
        private uint m_flags;
        private IList<pcap_addr> addrs;
        private IntPtr m_open_if;
        private pcap_pkt_handler m_pkthandler;

        private const int SNAPLEN = 65535;

        private pcap_if() { m_open_if = IntPtr.Zero; }

        public delegate void pcap_pkt_handler(pcap_pktdata pkt);
                
        public string name { get { return m_name; } }
        public string description { get { return m_description; } }
        public uint flags { get { return m_flags; } }

        public bool open(int snaplen = SNAPLEN)
        {
            if (m_open_if != IntPtr.Zero)
                return false;

            var error = new StringBuilder(libpcap.PCAP_ERRBUF_SIZE);
            m_open_if = libpcap.pcap_open(m_name, snaplen, 
                libpcap.PCAP_OPENFLAG_PROMISCUOUS, 0, IntPtr.Zero, error);

            if (m_open_if == IntPtr.Zero)
                return false;           

            return true;
        }

        public void close_if() { libpcap.pcap_close(m_open_if); }


        public bool loop_capture(pcap_pkt_handler handler)
        {
            if (m_open_if == IntPtr.Zero)
                return false;

            m_pkthandler = handler;

            return (libpcap.pcap_loop(m_open_if, -1, pcap_pkthandler, IntPtr.Zero) == 0);
        }

        public void pcap_breakloop()
        {
            if (m_open_if == IntPtr.Zero)
                return;

            libpcap.pcap_breakloop(m_open_if);
        }

        public bool send_packet(byte[] data)
        {
            if (m_open_if == IntPtr.Zero)
                return false;

            GCHandle pdata = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr pdataptr = pdata.AddrOfPinnedObject();

            int ret = 0;

            try
            {
                ret = libpcap.pcap_sendpacket(m_open_if, pdataptr, data.Length);
            }
            finally
            {
                pdata.Free();
            }           

            return (ret == 0);
        }

        public string dump()
        {
            var addrs_all = new StringBuilder();
            addrs_all.AppendLine();

            foreach (var it in addrs)
                addrs_all.AppendLine(it.dump());

            return name + ":" + description + ":" + flags + addrs_all;
        }

        public static IList<pcap_if> findalldevs()
        {
            IntPtr alldevsp = IntPtr.Zero;
            StringBuilder error = new StringBuilder(libpcap.PCAP_ERRBUF_SIZE);

            if (libpcap.pcap_findalldevs(ref alldevsp, error) < 0)
                return null;

            try
            {
                var all = new List<pcap_if>();
                pcap_if_t dev = (pcap_if_t)Marshal.PtrToStructure(alldevsp, typeof(pcap_if_t));                
                all.Add(get_if(dev));

                while (dev.next != IntPtr.Zero)
                {
                    dev = (pcap_if_t)Marshal.PtrToStructure(dev.next, typeof(pcap_if_t));
                    all.Add(get_if(dev));
                }

                return all;
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                libpcap.pcap_freealldevs(alldevsp);
            }            
        }

        public static void dumpalldevs(TextWriter output)
        {
            var alldevs = findalldevs();
            if (alldevs == null)
                return;

            foreach (var it in alldevs)
                output.WriteLine(it.dump());
        }

        private static pcap_if get_if(pcap_if_t ifdata)
        {
            
            return new pcap_if()
            {
                m_description = Marshal.PtrToStringAnsi(ifdata.description),
                m_name = Marshal.PtrToStringAnsi(ifdata.name),
                m_flags = ifdata.flags,
                addrs = pcap_addr.get_addresses(ifdata.addresses)
            };
        }

        internal void pcap_pkthandler(IntPtr user, IntPtr h, IntPtr bytes)
        {
            if (m_pkthandler == null)
                return;

            var hd = (pcap_pkthdr_t)Marshal.PtrToStructure(h, typeof(pcap_pkthdr_t));

            if (hd.caplen == 0)
                return;

            if (hd.caplen > hd.len)
                return;

            var payload = new byte[hd.caplen];
            Marshal.Copy(bytes, payload, 0, (int)hd.caplen);

            m_pkthandler(new pcap_pktdata
            {
                header = hd,
                payload = payload

            });
        }
    }
}
