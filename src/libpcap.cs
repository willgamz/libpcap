using System;
using System.Runtime.InteropServices;
using System.Text;

namespace pcap
{
    [StructLayout(LayoutKind.Sequential)]
    public struct pcap_if_t
    {
        public IntPtr next;
        public IntPtr name;
        public IntPtr description;
        public IntPtr addresses;
        public uint flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct pcap_addr_t
    {
        public IntPtr next;
        public IntPtr addr;
        public IntPtr netmask;
        public IntPtr broadaddr;
        public IntPtr dstaddr;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_t
    {
        public ushort sa_family;
        public IntPtr sa_data;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct timeval
    {
        public uint tv_sec;
        public uint tv_usec;
    }    

    [StructLayout(LayoutKind.Sequential)]
    public struct pcap_pkthdr_t
    {
        public timeval ts;
        public uint caplen;
        public uint len;    
    };

    internal static class libpcap
    {
        internal const string lib = "wpcap.dll";

        internal const int PCAP_ERRBUF_SIZE = 256;

        internal const int PCAP_D_IN = 0;
        internal const int PCAP_D_OUT = 0;
        internal const int PCAP_D_INOUT = 0;

        internal const int PCAP_OPENFLAG_PROMISCUOUS = 1;

        //int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_findalldevs(ref IntPtr alldevsp, StringBuilder errbuf);
      
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_freealldevs(IntPtr alldevs);

        [DllImport(lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open_live(string dev, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
        //
        //pcap_t* pcap_open(const char* source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth* auth, char* errbuf)
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open(string source, int snaplen, int flags, int read_timeout, IntPtr auth, StringBuilder errbuf);

        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_close(IntPtr p);

        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_sendpacket(IntPtr pcapif, byte[] buf, int size);

        //typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char* bytes);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal delegate void pcap_handler(
            [In, Out] IntPtr user,
            [In, Out] IntPtr h,
            [In, Out] IntPtr bytes);

        //int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user);
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern int pcap_loop(
            [In] IntPtr p,
            [In] int cnt,
            [In] [MarshalAs(UnmanagedType.FunctionPtr)] pcap_handler callback,
            [In] IntPtr user);

        
        //void pcap_breakloop(pcap_t* )
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_breakloop(IntPtr p);

        //int pcap_set_snaplen(pcap_t* p, int snaplen);
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_snaplen(IntPtr pcapif, int snaplen);

        //int pcap_next_ex(pcap_t* p, struct pcap_pkthdr **pkt_header, const u_char** pkt_data);
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_next_ex(
            [In] IntPtr pcapif,
            [In, Out] ref IntPtr pkt_header,
            [In, Out] ref IntPtr pkt_data);

        //const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
        [DllImport(lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pcap_next(IntPtr pcapif, IntPtr h);

    }
}
