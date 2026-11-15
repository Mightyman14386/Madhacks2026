"""GeoIP lookups backed by local MaxMind GeoLite2 files, with a deterministic fallback.

Nothing in this module raises to callers: every lookup failure returns None.
"""
import hashlib
import ipaddress
import logging
from functools import lru_cache

import config

log = logging.getLogger("geotrench.geo")

_city_reader = None
_asn_reader = None

# True when the City database is unavailable and lookups use the built-in table.
geoip_is_fallback = True

# (city, country_code, country_name, lat, lng)
_FALLBACK_CITIES = (
    ("New York", "US", "United States", 40.7128, -74.0060),
    ("Los Angeles", "US", "United States", 34.0522, -118.2437),
    ("Chicago", "US", "United States", 41.8781, -87.6298),
    ("Seattle", "US", "United States", 47.6062, -122.3321),
    ("Ashburn", "US", "United States", 39.0438, -77.4874),
    ("Toronto", "CA", "Canada", 43.6532, -79.3832),
    ("Mexico City", "MX", "Mexico", 19.4326, -99.1332),
    ("Bogotá", "CO", "Colombia", 4.7110, -74.0721),
    ("Lima", "PE", "Peru", -12.0464, -77.0428),
    ("Santiago", "CL", "Chile", -33.4489, -70.6693),
    ("São Paulo", "BR", "Brazil", -23.5505, -46.6333),
    ("Buenos Aires", "AR", "Argentina", -34.6037, -58.3816),
    ("London", "GB", "United Kingdom", 51.5074, -0.1278),
    ("Dublin", "IE", "Ireland", 53.3498, -6.2603),
    ("Paris", "FR", "France", 48.8566, 2.3522),
    ("Madrid", "ES", "Spain", 40.4168, -3.7038),
    ("Amsterdam", "NL", "Netherlands", 52.3676, 4.9041),
    ("Frankfurt", "DE", "Germany", 50.1109, 8.6821),
    ("Berlin", "DE", "Germany", 52.5200, 13.4050),
    ("Zurich", "CH", "Switzerland", 47.3769, 8.5417),
    ("Rome", "IT", "Italy", 41.9028, 12.4964),
    ("Stockholm", "SE", "Sweden", 59.3293, 18.0686),
    ("Warsaw", "PL", "Poland", 52.2297, 21.0122),
    ("Kyiv", "UA", "Ukraine", 50.4501, 30.5234),
    ("Moscow", "RU", "Russia", 55.7558, 37.6173),
    ("Istanbul", "TR", "Turkey", 41.0082, 28.9784),
    ("Cairo", "EG", "Egypt", 30.0444, 31.2357),
    ("Casablanca", "MA", "Morocco", 33.5731, -7.5898),
    ("Lagos", "NG", "Nigeria", 6.5244, 3.3792),
    ("Nairobi", "KE", "Kenya", -1.2921, 36.8219),
    ("Johannesburg", "ZA", "South Africa", -26.2041, 28.0473),
    ("Tel Aviv", "IL", "Israel", 32.0853, 34.7818),
    ("Riyadh", "SA", "Saudi Arabia", 24.7136, 46.6753),
    ("Dubai", "AE", "United Arab Emirates", 25.2048, 55.2708),
    ("Tehran", "IR", "Iran", 35.6892, 51.3890),
    ("Karachi", "PK", "Pakistan", 24.8607, 67.0011),
    ("Delhi", "IN", "India", 28.7041, 77.1025),
    ("Mumbai", "IN", "India", 19.0760, 72.8777),
    ("Bangalore", "IN", "India", 12.9716, 77.5946),
    ("Dhaka", "BD", "Bangladesh", 23.8103, 90.4125),
    ("Bangkok", "TH", "Thailand", 13.7563, 100.5018),
    ("Kuala Lumpur", "MY", "Malaysia", 3.1390, 101.6869),
    ("Singapore", "SG", "Singapore", 1.3521, 103.8198),
    ("Jakarta", "ID", "Indonesia", -6.2088, 106.8456),
    ("Manila", "PH", "Philippines", 14.5995, 120.9842),
    ("Hong Kong", "HK", "Hong Kong", 22.3193, 114.1694),
    ("Shanghai", "CN", "China", 31.2304, 121.4737),
    ("Beijing", "CN", "China", 39.9042, 116.4074),
    ("Taipei", "TW", "Taiwan", 25.0330, 121.5654),
    ("Seoul", "KR", "South Korea", 37.5665, 126.9780),
    ("Tokyo", "JP", "Japan", 35.6762, 139.6503),
    ("Sydney", "AU", "Australia", -33.8688, 151.2093),
    ("Melbourne", "AU", "Australia", -37.8136, 144.9631),
    ("Auckland", "NZ", "New Zealand", -36.8485, 174.7633),
)


# Known anycast ranges: one address served from many locations worldwide, so any
# single lat/lng would be misleading. Extend this list as new providers show up.
# (cidr, provider)
_ANYCAST_RANGES_RAW = (
    ("1.1.1.0/24", "Cloudflare DNS"),
    ("1.0.0.0/24", "Cloudflare DNS"),
    ("2606:4700:4700::/48", "Cloudflare DNS"),
    ("8.8.8.0/24", "Google Public DNS"),
    ("8.8.4.0/24", "Google Public DNS"),
    ("2001:4860:4860::/48", "Google Public DNS"),
    ("9.9.9.0/24", "Quad9 DNS"),
    ("149.112.112.0/24", "Quad9 DNS"),
    ("2620:fe::/48", "Quad9 DNS"),
    ("208.67.222.0/24", "OpenDNS"),
    ("208.67.220.0/24", "OpenDNS"),
    ("2620:119:35::/48", "OpenDNS"),
    ("2620:119:53::/48", "OpenDNS"),
    ("94.140.14.0/24", "AdGuard DNS"),
    ("94.140.15.0/24", "AdGuard DNS"),
)
_ANYCAST_RANGES = tuple((ipaddress.ip_network(cidr), name) for cidr, name in _ANYCAST_RANGES_RAW)


def anycast_provider(ip):
    """Return the provider name if ip is in a known anycast range, else None. Never raises."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        for net, name in _ANYCAST_RANGES:
            if addr.version == net.version and addr in net:
                return name
    except Exception:
        pass
    return None


def _open_reader(path, label):
    try:
        import geoip2.database
        reader = geoip2.database.Reader(str(path))
        log.info("MaxMind %s DB opened: %s", label, path)
        return reader
    except Exception as e:
        log.warning("MaxMind %s DB unavailable (%s): %s", label, path, e)
        return None


def init():
    """Open the MaxMind readers. Safe to call more than once."""
    global _city_reader, _asn_reader, geoip_is_fallback
    close()
    _city_reader = _open_reader(config.MAXMIND_CITY_PATH, "City")
    _asn_reader = _open_reader(config.MAXMIND_ASN_PATH, "ASN")
    geoip_is_fallback = _city_reader is None
    _lookup.cache_clear()


def close():
    global _city_reader, _asn_reader
    for reader in (_city_reader, _asn_reader):
        try:
            if reader is not None:
                reader.close()
        except Exception:
            pass
    _city_reader = None
    _asn_reader = None


def readers_loaded():
    """True only if both the City and ASN readers actually opened."""
    return _city_reader is not None and _asn_reader is not None


def classify_ip(ip):
    """Return 'public', 'invalid', or the reason the IP is not routable on the internet."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "invalid"
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or addr.is_reserved:
        return "reserved"
    if addr.is_private or not addr.is_global:
        return "private"
    return "public"


def _asn_org(ip):
    if _asn_reader is None:
        return None
    try:
        return _asn_reader.asn(ip).autonomous_system_organization
    except Exception:
        return None


def _fallback_city(ip):
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    index = int.from_bytes(digest[:8], "big") % len(_FALLBACK_CITIES)
    return _FALLBACK_CITIES[index]


@lru_cache(maxsize=2048)
def _lookup(ip):
    try:
        if classify_ip(ip) != "public":
            return None
        ip = str(ipaddress.ip_address(ip.strip()))  # normalize so the hash is stable

        provider = anycast_provider(ip)
        if provider is not None:
            return {
                "lat": None,
                "lng": None,
                "country_code": None,
                "country_name": None,
                "city": None,
                "asn_org": _asn_org(ip),
                "anycast": True,
                "anycast_provider": provider,
            }

        if _city_reader is None:
            city, cc, country, lat, lng = _fallback_city(ip)
            return {
                "lat": lat,
                "lng": lng,
                "country_code": cc,
                "country_name": country,
                "city": city,
                "asn_org": _asn_org(ip),
                "anycast": False,
                "anycast_provider": None,
            }

        resp = _city_reader.city(ip)
        lat, lng = resp.location.latitude, resp.location.longitude
        if lat is None or lng is None:
            return None
        country = resp.country if resp.country.iso_code else resp.registered_country
        return {
            "lat": lat,
            "lng": lng,
            "country_code": country.iso_code,
            "country_name": country.name,
            "city": resp.city.name,
            "asn_org": _asn_org(ip),
            "anycast": False,
            "anycast_provider": None,
        }
    except Exception:
        return None


def geolocate(ip):
    """Geolocate a public IP. Returns a dict or None. Never raises."""
    try:
        result = _lookup(str(ip))
        return dict(result) if result is not None else None  # copy so callers can't corrupt the cache
    except Exception:
        return None


def get_origin():
    return {"lat": config.ORIGIN_LAT, "lng": config.ORIGIN_LNG, "name": config.ORIGIN_NAME}
