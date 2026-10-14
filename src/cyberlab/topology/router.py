"""Virtual IP router with longest-prefix-match forwarding and subnet topology tracing."""

import ipaddress

from cyberlab.models.topology import RouteEntry, Subnet, VirtualHost


class VirtualRouter:
    """Manages routing tables, subnet address resolution, and virtual hop tracing."""

    def __init__(
        self,
        subnets: list[Subnet] | None = None,
        routes: list[RouteEntry] | None = None,
    ) -> None:
        """Initialize router with subnets and optional static routes."""
        self._subnets: dict[str, Subnet] = {}
        self._routes: list[RouteEntry] = []
        if subnets:
            for s in subnets:
                self.add_subnet(s)
        if routes:
            for r in routes:
                self.add_route(r)

    @property
    def subnets(self) -> list[Subnet]:
        """Return list of managed subnets."""
        return list(self._subnets.values())

    @property
    def routes(self) -> list[RouteEntry]:
        """Return static routing table entries."""
        return list(self._routes)

    def add_subnet(self, subnet: Subnet) -> None:
        """Register a new virtual subnet."""
        self._subnets[subnet.subnet_id] = subnet

    def remove_subnet(self, subnet_id: str) -> bool:
        """Remove a subnet by ID."""
        if subnet_id in self._subnets:
            del self._subnets[subnet_id]
            return True
        return False

    def add_route(self, route: RouteEntry) -> None:
        """Add a static route entry to the routing table."""
        self._routes.append(route)

    def find_subnet_by_ip(self, ip_str: str) -> Subnet | None:
        """Identify which subnet contains the given IPv4 address."""
        try:
            target_ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for subnet in self._subnets.values():
            try:
                network = ipaddress.ip_network(subnet.cidr, strict=False)
                if target_ip in network:
                    return subnet
            except ValueError:
                continue
        return None

    def find_host_by_id(self, host_id: str) -> VirtualHost | None:
        """Locate a host by its unique identifier across all subnets."""
        for subnet in self._subnets.values():
            for host in subnet.hosts:
                if host.host_id == host_id:
                    return host
        return None

    def find_host_by_ip(self, ip_str: str) -> VirtualHost | None:
        """Locate a host by its IP address across all subnets."""
        for subnet in self._subnets.values():
            for host in subnet.hosts:
                if host.ip_address == ip_str:
                    return host
        return None

    def resolve_next_hop(self, dest_ip_str: str) -> RouteEntry | None:
        """Perform longest-prefix match on destination IP address.

        Returns matching RouteEntry or None if no route found.
        """
        try:
            target_ip = ipaddress.ip_address(dest_ip_str)
        except ValueError:
            return None

        best_match: RouteEntry | None = None
        longest_prefix_len = -1

        for route in self._routes:
            try:
                network = ipaddress.ip_network(route.destination_cidr, strict=False)
                if target_ip in network and network.prefixlen > longest_prefix_len:
                    longest_prefix_len = network.prefixlen
                    best_match = route
            except ValueError:
                continue

        return best_match

    def trace_path(self, source_ip_str: str, dest_ip_str: str) -> list[str]:
        """Compute the sequence of subnet IDs traversed between source and destination."""
        src_sub = self.find_subnet_by_ip(source_ip_str)
        dst_sub = self.find_subnet_by_ip(dest_ip_str)

        path: list[str] = []
        if src_sub:
            path.append(src_sub.subnet_id)
        if dst_sub and dst_sub != src_sub:
            path.append(dst_sub.subnet_id)
        return path
