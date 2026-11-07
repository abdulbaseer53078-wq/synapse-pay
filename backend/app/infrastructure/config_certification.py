class ConfigCertificationRegistry:
    """Certified firmware versions per device model, from config.

    shortcut: a static list; replace with the Step 26 certification registry (which also supplies
    certification_profile_id) when it exists.
    """

    def __init__(self, certified: dict[str, set[str]]):
        self.certified = certified

    def is_certified(self, device_model: str, firmware_version: str) -> bool:
        return firmware_version in self.certified.get(device_model, set())
