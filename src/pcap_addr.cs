using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace pcap
{
    public class pcap_addr
    {
        private pcap_addr_t m_addr;

        private static sockaddr_t empy_addr()
        {
            sockaddr_t init;
            init.sa_data = IntPtr.Zero;
            init.sa_family = 0;

            return init;
        }

        public sockaddr_t addr
        {
            get { return m_addr.addr != IntPtr.Zero ? 
                    (sockaddr_t)Marshal.PtrToStructure(m_addr.addr, typeof(sockaddr_t)) : empy_addr(); }
        }

        public sockaddr_t netmask
        {
            get
            {
                return m_addr.netmask != IntPtr.Zero ?
                  (sockaddr_t)Marshal.PtrToStructure(m_addr.netmask, typeof(sockaddr_t)) : empy_addr();
            }
        }

        public sockaddr_t broadaddr
        {
            get
            {
                return m_addr.broadaddr != IntPtr.Zero ?
                  (sockaddr_t)Marshal.PtrToStructure(m_addr.broadaddr, typeof(sockaddr_t)) : empy_addr();
            }
        }

        public sockaddr_t dstaddr
        {
            get
            {
                return m_addr.dstaddr != IntPtr.Zero ?
                  (sockaddr_t)Marshal.PtrToStructure(m_addr.dstaddr, typeof(sockaddr_t)) : empy_addr();
            }
        }

        public string addr_string { get { return winsockets.getname(m_addr.addr); } }

        public string netmask_string { get { return winsockets.getname(m_addr.netmask); } }

        public string broadaddr_string { get { return winsockets.getname(m_addr.broadaddr); } }

        public string dstaddr_string { get { return winsockets.getname(m_addr.dstaddr); } }

        public string dump()
        {
            return String.Format("addr: {0}, netmask: {1}, broadcast: {2}, dst: {3}", 
                addr_string, netmask_string, broadaddr_string, dstaddr_string);
        }

        private pcap_addr() { }

        public static IList<pcap_addr> get_addresses(IntPtr addr)
        {
            var addrs = (pcap_addr_t)Marshal.PtrToStructure(addr, typeof(pcap_addr_t));

            var all = new List<pcap_addr>();
            all.Add(new pcap_addr {  m_addr = addrs });

            while (addrs.next != IntPtr.Zero)
            {
                addrs = (pcap_addr_t)Marshal.PtrToStructure(addrs.next, typeof(pcap_addr_t));
                all.Add(new pcap_addr { m_addr = addrs });
            }

            return all;
        }       
    }
}
