using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Managed
{
    public static class WinApiHelper
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
    }
}
