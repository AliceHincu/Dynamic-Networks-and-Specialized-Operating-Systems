from pywifi import PyWiFi, const
from mac_vendor_lookup import MacLookup
import matplotlib.pyplot as plt

# used for accessing and controlling system's wi-fi network cards
wifi = PyWiFi()
iface = wifi.interfaces()[0]
# used to access vendors (manufacturer of networks cards)
mac_lookup = MacLookup()
# update_vendors()

def update_vendors():
    """
    Update list of vendors. make sure to have a folder named ".cache" under your user on your pc. this can be ran only one time
    """
    print("Getting the list of vendors, this can take a few seconds...")
    mac_lookup.update_vendors()
    print("The vendors are up to date, the app should start now.")


def get_manufacturer(mac_address):
    """
    Return the manufacturer of a device based on its MAC address.
    """
    try:
        return mac_lookup.lookup(mac_address)
    except KeyError:
        return "Unknown"

def scan_wifi():
    """
    Access network cards to scan all Wi-Fi networks and return them
    """
    iface.scan()
    return iface.scan_results()

def classify_signal(signal_strength):
    """
    Classify the signal strength and return a corresponding color
    """
    if signal_strength > -70:
        return "images/wifi-icon-green.png", "#04ff00"
    elif signal_strength >= -85:
        return "images/wifi-icon-yellow.png", "#fbff00"
    else:
        return "images/wifi-icon-red.png", "#ff2600"

def parse_security(akm_list):
    """
    Parse the security details from the akm list and return a readable format.
    WPA = Wi-Fi Protected Access
    PSK = Pre-Shared Key
    WPA -> unique auth for each user , PSK -> common password for everyone
    """
    akm_mapping = {
        const.AKM_TYPE_NONE: "Open",
        const.AKM_TYPE_WPA: "WPA",
        const.AKM_TYPE_WPAPSK: "WPAPSK",
        const.AKM_TYPE_WPA2: "WPA2",
        const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
    }
    return ", ".join(akm_mapping.get(akm, "Unknown") for akm in akm_list)

def calculate_channel(freq):
    """
    Calculate the Wi-Fi channel based on the frequency (in MHz).
    Source: https://en.wikipedia.org/wiki/List_of_WLAN_channels?utm_source=chatgpt.com
    - 14 channels are designated in the 2.4 GHz range, spaced 5 MHz apart from each other except for a 12 MHz space before channel 14
    - channels between this range: [36, 165] are designated in the 5 GHz range, spaced 2- MHz apart - but this rule depends on the region
    """
    if 2400 <= freq <= 2500:  # 2.4 GHz range
        return (freq - 2407) // 5
    elif 5000 <= freq <= 6000:  # 5 GHz range
        return (freq - 5180) // 20 + 36
    else:
        return "Unknown"


def plot_channels(networks, canvas):
    """
    Generate and update the channel usage chart
    """
    plt.clf()
    channel_counts = {}
    for network in networks:
        channel = int(network.freq / 5 % 1000 - 2407)
        channel_counts[channel] = channel_counts.get(channel, 0) + 1

    channels = list(channel_counts.keys())
    counts = [channel_counts[ch] for ch in channels]
    plt.bar(channels, counts, color='blue')
    canvas.draw()
