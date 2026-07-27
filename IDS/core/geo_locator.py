import requests
import ipaddress


def is_private_ip(ip):

    try:
        ip_obj = ipaddress.ip_address(ip)

        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )

    except:
        return True


def get_geolocation(ip):

    # Local/private network
    if is_private_ip(ip):

        return {
            "country": "LOCAL NETWORK",
            "city": "Private IP",
            "region": "LAN",
            "isp": "Internal Network",
            "lat": 0,
            "lon": 0
        }

    try:

        url = f"http://ip-api.com/json/{ip}"

        response = requests.get(
            url,
            timeout=5
        )

        data = response.json()

        if data["status"] == "success":

            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0)
            }

    except:
        pass

    return {
        "country": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "isp": "Unknown",
        "lat": 0,
        "lon": 0
    }