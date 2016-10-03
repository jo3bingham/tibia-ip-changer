using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Windows;
using Tibia.Utilities;

namespace Tibia
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            uxClientPath.Text = Constants.DefaultClientPath;
        }

        private void uxBrowse_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new System.Windows.Forms.OpenFileDialog() { Filter = "Tibia Client (*.exe)|*.exe" };
            openFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                uxClientPath.Text = openFileDialog.FileName;
            }
        }

        private void uxApply_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (uxClientPath.Text == string.Empty || !uxClientPath.Text.Contains(".exe"))
                {
                    MessageBox.Show("Client path is not valid.");
                    return;
                }

                if (uxIP.Text.Equals(string.Empty))
                {
                    MessageBox.Show("IP is not valid.");
                    return;
                }

                ushort port;
                if (uxPort.Text.Equals(string.Empty) || !ushort.TryParse(uxPort.Text, out port))
                {
                    MessageBox.Show("Port is not valid.");
                    return;
                }

                Environment.CurrentDirectory = uxClientPath.Text.Replace("Tibia.exe", "");
                Process process = Process.Start(uxClientPath.Text);

                process.WaitForInputIdle();
                while (process.MainWindowHandle == IntPtr.Zero)
                {
                    process.Refresh();
                    Thread.Sleep(5);
                }

                var version = FileVersionInfo.GetVersionInfo(uxClientPath.Text).FileVersion;
                if (version == "1, 0, 0, 1")
                {
                    version = "7.0.0";
                }

                var versionNumber = int.Parse(version.Replace(".", ""));
                var baseAddress = (uint)process.MainModule.BaseAddress.ToInt32();
                var processHandle = WinAPI.OpenProcess((WinAPI.PROCESS_VM_READ | WinAPI.PROCESS_VM_WRITE | WinAPI.PROCESS_VM_OPERATION), 0, (uint)process.Id);
                var buffer = Memory.ReadBytes(processHandle, baseAddress, (uint)process.MainModule.ModuleMemorySize);

                uint loginServerStart = 0;
                if (versionNumber >= 10110)
                {
                    loginServerStart = Memory.ScanBytes(buffer, Constants.LoginServerArrayCurrent) + baseAddress;
                    loginServerStart = Memory.ReadUInt32(processHandle, loginServerStart - Constants.LoginServerStartOffsetCurrent) - baseAddress;
                }
                else if (versionNumber >= 800)
                {
                    loginServerStart = Memory.ScanBytes(buffer, Constants.LoginServerArrayPre10110) + baseAddress;
                    loginServerStart = Memory.ReadUInt32(processHandle, loginServerStart + Constants.LoginServerStartOffsetPre10110) - baseAddress;
                }
                else
                {
                    loginServerStart = Memory.ScanBytes(buffer, Constants.LoginServerArrayPre8000) + baseAddress;
                    loginServerStart = Memory.ReadUInt32(processHandle, loginServerStart + Constants.LoginServerStartOffsetPre8000) - baseAddress;
                }

                uint loginServerEnd = 0;
                uint loginServerStep = 0;
                uint loginServerHostnamePtrOffset = 0;
                uint loginServerIpPtrOffset = 0;
                uint loginServerPortOffset = 0;
                uint loginServerCount = 0;
                if (versionNumber >= 10500)
                {
                    loginServerEnd = loginServerStart + 0x04;
                    loginServerStep = 0x30;
                    loginServerHostnamePtrOffset = 0x04;
                    loginServerIpPtrOffset = 0x1C;
                    loginServerPortOffset = 0x28;
                }
                else if (versionNumber >= 10110)
                {
                    loginServerEnd = loginServerStart + 0x04;
                    loginServerStep = 0x38;
                    loginServerHostnamePtrOffset = 0x04;
                    loginServerIpPtrOffset = 0x20;
                    loginServerPortOffset = 0x30;
                    loginServerCount = 0x0A;
                }
                else if (versionNumber >= 800)
                {
                    loginServerStep = 0x70;
                    loginServerPortOffset = 0x64;
                    loginServerCount = 0x0A;
                }
                else
                {
                    loginServerStep = 0x70;
                    loginServerPortOffset = 0x64;
                    loginServerCount = 0x04;
                }

                uint rsaKey = 0;
                if (versionNumber >= 861)
                {
                    rsaKey = Memory.ScanString(buffer, Constants.RsaKeyCurrent);
                }
                else if (versionNumber >= 772)
                {
                    rsaKey = Memory.ScanString(buffer, Constants.RsaKeyOld);
                }

                process.Kill();

                var pi = new WinAPI.PROCESS_INFORMATION();
                var si = new WinAPI.STARTUPINFO();

                if (!WinAPI.CreateProcess(uxClientPath.Text, " ", IntPtr.Zero, IntPtr.Zero, false, WinAPI.CREATE_SUSPENDED, IntPtr.Zero, System.IO.Path.GetDirectoryName(uxClientPath.Text), ref si, out pi))
                {
                    return;
                }

                processHandle = pi.hProcess;
                process = Process.GetProcessById(Convert.ToInt32(pi.dwProcessId));
                baseAddress = (uint)WinAPI.GetBaseAddress(processHandle).ToInt32();

                WinAPI.ResumeThread(pi.hThread);
                process.WaitForInputIdle();
                WinAPI.CloseHandle(pi.hThread);

                while (process.MainWindowHandle == IntPtr.Zero)
                {
                    process.Refresh();
                    Thread.Sleep(5);
                }

                var resolvedIp = uxIP.Text;
                IPAddress ipa;
                if (!IPAddress.TryParse(uxIP.Text, out ipa))
                {
                    IPAddress[] addressList = Dns.GetHostEntry(uxIP.Text).AddressList;

                    if (addressList.Length > 0)
                    {
                        resolvedIp = addressList[0].ToString();
                    }
                }

                if (versionNumber >= 10110)
                {
                    uint loginStart = Memory.ReadUInt32(processHandle, loginServerStart + baseAddress);
                    uint loginEnd = Memory.ReadUInt32(processHandle, loginServerEnd + baseAddress);

                    for (uint loginServer = loginStart; loginServer < loginEnd; loginServer += loginServerStep)
                    {
                        uint ipAddress = Memory.ReadUInt32(processHandle, loginServer + loginServerIpPtrOffset);
                        Memory.WriteInt32(processHandle, ipAddress, 0);

                        uint hostAddress = Memory.ReadUInt32(processHandle, loginServer + loginServerHostnamePtrOffset);
                        Memory.WriteString(processHandle, hostAddress, resolvedIp);

                        uint portAddress = loginServer + loginServerPortOffset;
                        var portValue = BitConverter.ToUInt16(Memory.ReadBytes(processHandle, portAddress, 2), 0);
                        Memory.WriteUInt16(processHandle, portAddress, port);
                    }
                }
                else
                {
                    uint loginServer = loginServerStart + baseAddress;

                    for (int i = 0; i < loginServerCount; ++i)
                    {
                        Memory.WriteString(processHandle, loginServer, resolvedIp);
                        Memory.WriteUInt16(processHandle, loginServer + loginServerPortOffset, port);
                        loginServer += loginServerStep;
                    }
                }

                if (versionNumber >= 772)
                {
                    Memory.WriteRsa(processHandle, (rsaKey + baseAddress), Constants.RsaKeyOpenTibia);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
