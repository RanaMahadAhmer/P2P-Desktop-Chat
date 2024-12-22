import psutil
import ipaddress
import socket


def get_working_private_ip():
    """Find the private IP address associated with the network interface that has the most traffic."""
    # Get network stats (sent/received bytes) for all interfaces
    io_counters = psutil.net_io_counters(pernic=True)
    private_ip_with_traffic = {}

    # Iterate over all network interfaces
    for iface, addrs in psutil.net_if_addrs().items():
        # Get the traffic for the interface
        traffic = io_counters.get(iface)
        if not traffic:
            continue
        total_traffic = traffic.bytes_sent + traffic.bytes_recv

        # Check all IP addresses associated with the interface
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Only IPv4
                ip = addr.address
                ip_obj = ipaddress.ip_address(ip)
                # Check if the IP is private and in Class A, B, or C range
                if ip_obj.is_private:
                    if (ip_obj in ipaddress.IPv4Network("10.0.0.0/8") or
                        ip_obj in ipaddress.IPv4Network("172.16.0.0/12") or
                        ip_obj in ipaddress.IPv4Network("192.168.0.0/16")):
                        private_ip_with_traffic[ip] = total_traffic

    # Find the private IP with the most traffic
    if private_ip_with_traffic:
        most_traffic_ip = max(private_ip_with_traffic, key=private_ip_with_traffic.get)
        return most_traffic_ip, private_ip_with_traffic[most_traffic_ip]
    else:
        return None, 0
