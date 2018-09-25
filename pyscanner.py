import sys
import argparse
import socket
import os
import ipaddress
import subprocess
import multiprocessing as mp
import math


# is_alive
# Pings the target to see if it is alive
# will be fed a list of hosts from find_hosts through multiprocessing.Pool.map()
def is_alive(target):
    with open(os.devnull, 'w') as trash:
        result = subprocess.call("ping -W 2 -c 1 " + target, stderr=trash, stdout=trash)  # linux
        #result = subprocess.call("ping -w 2000 -n 1 " + target, stderr=trash, stdout=trash)  # windows
    if result == 0:
        print target + " is up"
        return target
    else:
        return None


def find_hosts(targets):
    network_hosts = list()
    active_hosts = list()
    for target in targets:
        try:
            # append a subnet if necessary and grab the host's network
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                pass
            network = ipaddress.IPv4Network(unicode(target, "utf-8"))
            print"Scanning {} hosts".format(network.num_addresses)
            # if there are more hosts on the subnet, add them to targets list
            if network.num_addresses > 1:
                hosts = network.hosts()
                for host in hosts:
                    network_hosts.append(str(host))
        except ipaddress.AddressValueError:
            print "Bad address: " + target
            sys.exit(1)
        except ValueError:
            print "Not a valid network: " + target
            sys.exit(1)

    # multithreading stuff
    num_threads = int(math.ceil(len(network_hosts)/5) + 1)
    proc = mp.Pool(num_threads)
    active_hosts = proc.map(is_alive, network_hosts)
    proc.close()
    proc.join()

    # map() puts a bunch of 'None's in the host list, so I gotta remove em
    active_hosts[:] = [host for host in active_hosts if host is not None]

    ret = targets + active_hosts
    return ret


# Scan
# Performs a TCP or UDP scan of every given port on every given target.
def scan(targets, ports, mode):
    filtered = [11, 111, 101, 10035]
    port_list = ports.split(",")
    try:
        for target in targets:
            target = target.split("/")[0]  # remove the mask so the host can be scanned
            total = 0  # count the number of ports scanned
            print target
            for port in port_list:
                # if a port range was given, loop through the range
                if ':' in port or '-' in port:
                    if ':' in port:
                        port_range = port.split(":")
                    if '-' in port:
                        port_range = port.split('-')

                    # parse the upper and lower bounds of the range
                    min_port = int(port_range[0])
                    max_port = int(port_range[1])
                    try:
                        while min_port <= max_port:
                            s = socket.socket(socket.AF_INET, mode)
                            result = s.connect_ex((target, min_port))
                            if result is None or result == 0:
                                print "Port {}: Open".format(min_port)
                            elif result not in filtered:  # ignore closed ports
                                print "Error code:", result
                            s.close()
                            min_port += 1
                            total += 1
                    except ValueError:
                        print "Bad port: " + min_port
                        sys.exit(1)
                else:
                    try:
                        s = socket.socket(socket.AF_INET, mode)
                        result = s.connect_ex((target, int(port)))
                        if result is None or result == 0:
                            print "Port {}: Open".format(port)
                        elif result not in filtered:  # ignore closed ports
                            print "Error code:", result
                        s.close()
                        total += 1
                    except ValueError:
                        print "Bad port: " + port
                        sys.exit(1)
            print str(total) + " ports scanned\n"
    except socket.gaierror:
        print target + " invalid host\n"
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    socket.setdefaulttimeout(0.075)

    parser.add_argument("target", default=None, nargs='+',
                        help="targets to scan in CIDR notation or FQDN")
    parser.add_argument("-p", "--port-range",
                        help="range of ports to scan (Default: '22,80,443:445'")
    parser.add_argument("-l", "--list-only", action="store_true",
                        help="list only, the hosts that will be scanned")
    parser.add_argument("-t", "-tcp", action="store_true",
                        default=False, help="TCP mode (default)")
    parser.add_argument("-u", "--udp", action="store_true",
                        default=False, help="UDP mode")

    args = parser.parse_args()
    args.target = find_hosts(args.target)

    print 'Target(s):' + str(args.target)
    # list only mode
    if args.list_only:
        print '\nMode: List only'
        for target in args.target:
            try:
                print socket.gethostbyname(target) + " - " + target
            except socket.gaierror:
                pass
    # if NOT network scan only, do the rest
    if args.port_range is not None or args.t or args.udp:
        if args.port_range is None:
            args.port_range = '22,80,443:445'
        print'Port Range: ' + args.port_range + "\n"

        # default to tcp scan if neither was specified
        if not args.udp and not args.t:
            args.t = True

        if args.t:
            print "Starting TCP scan"
            scan(args.target, args.port_range, socket.SOCK_STREAM)

        if args.udp:
            print "Starting UDP scan"
            scan(args.target, args.port_range, socket.SOCK_DGRAM)
    return 0


if __name__ == '__main__':
    sys.exit(main())
