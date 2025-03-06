import json


class VendorLookup:
    def __init__(self, json_file_path):
        """
        Initializes the VendorLookup class with a path to the JSON file containing OUI data.

        :param json_file_path: str, path to the JSON file
        """
        self.oui_data = self._load_oui_data(json_file_path)

    @staticmethod
    def _load_oui_data(json_file_path):
        """
        Loads OUI data from the specified JSON file.

        :param json_file_path: str, path to the JSON file
        :return: list, OUI data loaded from the file
        """
        try:
            with open(json_file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"OUI data file not found at {json_file_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON format in {json_file_path}")
        except Exception as e:
            raise RuntimeError(f"Error loading OUI data: {e}")

    def get_vendor(self, mac_address):
        """
        Fetches the vendor information for a given MAC address from the local OUI data.

        :param mac_address: str, the MAC address to look up
        :return: str, the vendor name or 'Unknown' if not found
        """
        if not mac_address or len(mac_address) < 6:
            return "Unknown"

        # Normalize the MAC address (remove delimiters and convert to uppercase)
        mac_prefix = mac_address.replace(":", "").replace("-", "").upper()[:6]
        for entry in self.oui_data:
            if entry.get("macPrefix", "").replace(":", "").replace("-", "").upper() == mac_prefix:
                return entry.get("vendorName", "Unknown")
        return "Unknown"
