using pcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace pcap
{
    public static class winsockets
    {
        internal static int NI_MAXSERV = 32;
        internal static int NI_MAXHOST = 1025;
        internal static int MAX_ADDRESS = 28;

        [Flags]
        internal enum NameInfoFlags : int
        {
            NI_NAMEREQD = 0x1,
            NI_NUMERICHOST = 0x2,
        }

        internal const string lib = "Ws2_32.dll";


        /*
            int WSAAPI getnameinfo(
                  _In_  const struct sockaddr FAR *sa,
                  _In_  socklen_t                 salen,
                  _Out_ char FAR                  *host,
                  _In_  DWORD                     hostlen,
                  _Out_ char FAR                  *serv,
                  _In_  DWORD                     servlen,
                  _In_  int                       flags
                ); 
        */
        [DllImport(lib, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
        internal static extern int getnameinfo(
                [In]         IntPtr sa,
                [In]         int salen,
                [In, Out]    StringBuilder host,
                [In]         int hostlen,
                [In, Out]    StringBuilder serv,
                [In]         int servlen,
                [In]         int flags);


        private static bool getnameinfo(IntPtr addr, StringBuilder hostname)
        {
            if (addr == IntPtr.Zero)
                return false;

            var servInfo = new StringBuilder(NI_MAXSERV);
            var addrs = (sockaddr_t)Marshal.PtrToStructure(addr, typeof(sockaddr_t));

            if (addrs.sa_data != IntPtr.Zero)
            {
                if (getnameinfo(addr, MAX_ADDRESS, hostname, NI_MAXHOST, servInfo, NI_MAXSERV, 2) != 0)
                    return false;
            }

            return true;
        }

        public static string getname(IntPtr addr)
        {
            StringBuilder hostname = new StringBuilder(NI_MAXHOST);
            getnameinfo(addr, hostname);

            return hostname.ToString();
        }
    }
}
