using PacketDotNet;
using SharpPcap;

namespace TrafficDecryptor
{
    internal class Program
    {
        static List<Packet> capturedPackets = new List<Packet>();
        static void Main(string[] args)
        {
            // List all devices
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found.");
                return;
            }

            Console.WriteLine("Captured Devices:");

            int id = 0;
            foreach (var device in devices)
            {
                Console.WriteLine($"[{id}]");
                Console.WriteLine(device);
                id++;
            }

            Console.WriteLine("Which device to sniff? (Enter [id] of target device)");
            int deviceIndex = int.Parse(Console.ReadLine()!);

            // Select the first available device
            StartCapture(devices, deviceIndex);
        }

        private static void StartCapture(CaptureDeviceList devices, int deviceIndex)
        {
            SharpPcap.ILiveDevice device = devices[deviceIndex];
            Console.WriteLine(device);
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();

            Console.WriteLine("Press Enter to stop...");
            Console.ReadLine();

            device.StopCapture();
            device.Close();

            // Perform analysis after capture
            AnalyzeCapturedPackets();
        }

        private static void Device_OnPacketArrival(object sender, SharpPcap.PacketCapture e)
        {
            SharpPcap.RawCapture packet = e.GetPacket();
            Console.WriteLine(packet);
            PacketDotNet.Packet parsedPacket = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
            capturedPackets.Add(parsedPacket);

            // For demonstration, we simply output info about the packet
            string path = "C:../../../traffic_log/log.txt";

            using (StreamWriter writer = new StreamWriter(path))
            {
                writer.WriteLine($"Date of capture: {DateTime.UtcNow.ToString()}");

                foreach (var entry in capturedPackets.ToList())
                {
                    writer.WriteLine($"Parsed packet: {parsedPacket}");
                    writer.WriteLine($"Payload packet: {parsedPacket.PayloadPacket}");
                    writer.WriteLine($"Payload data: {parsedPacket.PayloadData}");
                    writer.WriteLine($"Payload data segment: {parsedPacket.PayloadDataSegment}");
                }
            }
        }

        private static void AnalyzeCapturedPackets()
        {
            Console.WriteLine("\n*** Packet Analysis ***");

            // Count packets by type
            var packetTypes = capturedPackets.GroupBy(p => p.GetType().Name) 
                                              .Select(g => new { Type = g.Key, Count = g.Count() })
                                              .OrderByDescending(g => g.Count);

            if(packetTypes.Count() == 0)
            {
                Console.WriteLine("Did not capture any packets!");
                return;
            }

            
            

            Double averageSize = capturedPackets.Average(p => p.Bytes.Length);
            Console.WriteLine($"Average packet size: {averageSize} bytes");
        }
    }
}
