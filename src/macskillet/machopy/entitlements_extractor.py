import plistlib
import lief
import json
import signal

# pandas is only needed by the dataset-iteration helpers below, which are
# research utilities rather than part of the analysis path. Importing it at
# module scope made `portable`-only installs fail to read entitlements and
# certificates at all -- silently, since callers catch ImportError.
def _pandas():
    import pandas as pd

    return pd



# LOGGING_LEVEL was removed in LIEF 0.15; disable() is the supported API and
# exists across versions. The old call raised AttributeError at import time,
# which made this whole module unimportable on any modern LIEF.
lief.logging.disable()
DATASET_PATH = 'dataset_info.csv'
TIMEOUT_DEFAULT = 240


ENTITLEMENTS = {
    # Alternative Marketplaces
    "com.apple.developer.marketplace.app-installation": "Alternative Marketplaces",

    # App Clips
    "com.apple.developer.parent-application-identifiers": "App Clips",
    "com.apple.developer.associated-appclip-app-identifiers": "App Clips",
    "com.apple.developer.on-demand-install-capable": "App Clips",

    # Authentication
    "com.apple.developer.authentication-services.autofill-credential-provider": "Authentication",
    "com.apple.developer.applesignin": "Authentication",

    # CarPlay
    "com.apple.developer.carplay-audio": "CarPlay",
    "com.apple.developer.carplay-charging": "CarPlay",
    "com.apple.developer.carplay-communication": "CarPlay",
    "com.apple.developer.carplay-maps": "CarPlay",
    "com.apple.developer.carplay-parking": "CarPlay",
    "com.apple.developer.carplay-quick-ordering": "CarPlay",
    "com.apple.developer.carplay-messaging": "CarPlay",

    # Contacts
    "com.apple.developer.contacts.notes": "Contacts",

    # Device Management
    "com.apple.developer.automated-device-enrollment.add-devices": "Device Management",
    
    # Education
    "com.apple.developer.ClassKit-environment": "Education",
    
    # Enterprise - Email clients
    "com.apple.developer.mail-client": "Enterprise - Email clients",
    # Enterprise - Apple Neural Engine access
    "com.apple.developer.coreml.neural-engine-access": "Enterprise - Apple Neural Engine access",
    # Enterprise - Increased performance headroom
    "com.apple.developer.app-compute-category": "Enterprise - Increased performance headroom",
    # Enterprise - Passthrough in screen capture
    "com.apple.developer.screen-capture.include-passthrough": "Enterprise - Passthrough in screen capture",
    # Enterprise - Main camera access
    "com.apple.developer.arkit.main-camera-access.allow": "Enterprise - Main camera access",
    # Enterprise - Object-tracking parameter adjustment
    "com.apple.developer.arkit.object-tracking-parameter-adjustment.allow": "Enterprise - Object-tracking parameter adjustment",
    # Enterprise - Spatial barcode and QR code scanning
    "com.apple.developer.arkit.barcode-detection.allow": "Enterprise - Spatial barcode and QR code scanning",

    # Exposure notification
    "com.apple.developer.exposure-notification": "Exposure notification",

    # Family Controls
    "com.apple.developer.family-controls": "Family Controls",

    # File provider
    "com.apple.developer.fileprovider.testing-mode": "File provider",

    # Games
    "com.apple.developer.game-center": "Games",

    # Group activities
    "com.apple.developer.group-session": "Group activities",

    # Health
    "com.apple.developer.healthkit": "Health",
    "com.apple.developer.healthkit.access": "Health",
    "com.apple.developer.healthkit.background-delivery": "Health",
    "com.apple.developer.healthkit.recalibrate-estimates": "Health",

    # Home automation
    "com.apple.developer.homekit": "Home automation",

    # Hypervisor
    "com.apple.security.hypervisor": "Hypervisor",
    "com.apple.vm.hypervisor": "Hypervisor",
    "com.apple.vm.device-access": "Hypervisor",
    "com.apple.vm.networking": "Hypervisor",
    "com.apple.security.virtualization": "Hypervisor",

    # iCloud
    "com.apple.developer.icloud-container-development-container-identifiers": "iCloud",
    "com.apple.developer.icloud-container-environment": "iCloud",
    "com.apple.developer.icloud-container-identifiers": "iCloud",
    "com.apple.developer.icloud-services": "iCloud",
    # "com.apple.developer.ubiquity-kvstore-identifier": "iCloud",
    "com.apple.private.icloud-account-access": "iCloud",

    # Journaling Suggestions
    "com.apple.developer.journal.allow": "Journaling Suggestions",

    # Location
    "com.apple.developer.location.push": "Location",

    # Managed App Distribution
    "com.apple.developer.managed-app-distribution.install-ui": "Managed App Distribution",

    # Media
    "com.apple.developer.media-device-discovery-extension": "Media",
    "com.apple.developer.avfoundation.multitasking-camera-access": "Media",
    "com.apple.developer.coremotion.head-pose": "Media",
    "com.apple.developer.spatial-audio.profile-access": "Media",
    "com.apple.developer.sustained-execution": "Media",
    "com.apple.developer.arkit.main-camera-access.allow": "Media",
    "com.apple.developer.arkit.object-tracking-parameter-adjustment.allow": "Media",
    "com.apple.developer.arkit.barcode-detection.allow": "Media",

    # Memory
    "com.apple.developer.kernel.increased-memory-limit": "Memory",
    "com.apple.developer.kernel.extended-virtual-addressing": "Memory",

    # Metal
    "com.apple.developer.sustained-execution": "Metal",

    # MessageUI
    "com.apple.developer.upi-device-validation": "MessageUI",

    # Networking
    "com.apple.developer.networking.networkextension": "Networking",
    "com.apple.developer.networking.vpn.api": "Networking",
    "com.apple.developer.associated-domains": "Networking",
    "com.apple.developer.associated-domains.applinks.read-write": "Networking",
    "com.apple.developer.networking.manage-thread-network-credentials": "Networking",
    "com.apple.developer.networking.slicing.appcategory": "Networking",
    "com.apple.developer.networking.slicing.trafficcategory": "Networking",
    "com.apple.developer.networking.vmnet": "Networking",

    # Notifications
    "aps-environment": "Notifications",
    "com.apple.developer.aps-environment": "Notifications",
    "com.apple.developer.usernotifications.filtering": "Notifications",
    "com.apple.developer.usernotifications.time-sensitive": "Notifications",

    # Privacy
    "com.apple.developer.device-information.user-assigned-device-name": "Privacy",

    # Push to talk
    "Push to Talk Entitlement": "Push to talk",

    # SafetyKit
    "com.apple.developer.severe-vehicular-crash-event": "SafetyKit",

    # App Sandbox
    "com.apple.security.app-sandbox": "App Sandbox",

    # App Sandbox Entitlements - Network
    "com.apple.security.network.client": "App Sandbox - Network",
    "com.apple.security.network.server": "App Sandbox - Network",
    
    # App Sandbox Entitlements - Hardware
    "com.apple.security.device.camera": "App Sandbox - Hardware",
    "com.apple.security.device.microphone": "App Sandbox - Hardware",
    "com.apple.security.device.usb": "App Sandbox - Hardware",
    "com.apple.security.device.print": "App Sandbox - Hardware",
    "com.apple.security.device.bluetooth": "App Sandbox - Hardware",
    "com.apple.security.device.audio-input": "App Sandbox - Hardware",

    # App Sandbox Entitlements - Address Book
    "com.apple.security.personal-information.addressbook": "App Sandbox - Address Book",

    # App Sandbox Entitlements - Location
    "com.apple.security.personal-information.location": "App Sandbox - Location",

    # App Sandbox Entitlements - Calendars
    "com.apple.security.personal-information.calendars": "App Sandbox - Calendars",

    # App Sandbox Entitlements - File Access
    "com.apple.security.files.user-selected.read-only": "App Sandbox - File Access",
    "com.apple.security.files.user-selected.read-write": "App Sandbox - File Access",
    "com.apple.security.files.downloads.read-only": "App Sandbox - File Access",
    "com.apple.security.files.downloads.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.pictures.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.pictures.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.music.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.music.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.movies.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.movies.read-write": "App Sandbox - File Access",
    "com.apple.security.files.all": "App Sandbox - File Access",
    
    # App Sandbox Entitlements - Accessibility
    "com.apple.security.accessibility": "App Sandbox - Accessibility",
    
    # Hardened Runtime
    "com.apple.security.cs.allow-jit": "Hardened Runtime",
    "com.apple.security.cs.allow-unsigned-executable-memory": "Hardened Runtime",
    "com.apple.security.cs.allow-dyld-environment-variables": "Hardened Runtime",
    "com.apple.security.cs.disable-library-validation": "Hardened Runtime",
    "com.apple.security.cs.clear-library-validation": "Hardened Runtime",
    "com.apple.security.cs.disable-executable-page-protection": "Hardened Runtime",
    "com.apple.security.cs.debugger": "Hardened Runtime",
    # "com.apple.developer.kernel.extended-attribute-retrieval": "Hardenend Runtime",
    
    # App Groups Entitlement
    "com.apple.security.application-groups": "App Groups Entitlement",
    
    # Keychain Access Groups Entitlement
    "keychain-access-groups": "Keychain Access Groups Entitlement",
    
    # Data Protection Entitlement
    "com.apple.developer.default-data-protection": "Data Protection Entitlement",
    
    # App Attest Environment
    "com.apple.developer.devicecheck.appattest-environment": "App Attest Environment",
    
    # Smartcard Access
    "com.apple.security.smartcard": "Smartcard Access",

    # Sensitive content analysis
    "com.apple.developer.sensitivecontentanalysis.client": "Sensitive content analysis",

    # Sensors
    "com.apple.developer.sensorkit.reader.allow": "Sensors",

    # Siri
    "com.apple.developer.siri": "Siri",

    # StoreKit
    "com.apple.developer.storekit.external-link.account": "StoreKit",
    "com.apple.developer.storekit.external-purchase": "StoreKit",
    "com.apple.developer.storekit.external-purchase-link": "StoreKit",

    # System Extensions - Essential
    "com.apple.developer.system-extension.install": "System Extensions",
    "com.apple.developer.system-extension.redistributable": "System Extensions",

    # System Extensions - Endpoint Security
    "com.apple.developer.endpoint-security.client": "System Extensions - Endpoint Security",

    # System Extensions - Human Interface Device Drivers
    "com.apple.developer.driverkit": "System Extensions - Human Interface Device Drivers",
    "com.apple.developer.hid.virtual.device": "System Extensions - Human Interface Device Drivers",

    # TV
    "com.apple.developer.user-management": "TV",
    "com.apple.developer.video-subscriber-single-sign-on": "TV",
    "com.apple.smoot.subscriptionservice": "TV",

    # Wallet
    "com.apple.developer.pass-type-identifiers": "Wallet",
    "com.apple.developer.in-app-payments": "Wallet",
    "com.apple.developer.in-app-identity-presentment": "Wallet",
    "com.apple.developer.in-app-identity-presentment.merchant-identifiers": "Wallet",

    # WeatherKit
    "com.apple.developer.weatherkit": "WeatherKit",

    # Web browsers
    "com.apple.developer.web-browser": "Web browsers",
    "com.apple.developer.web-browser.public-key-credential": "Web browsers",
    "com.apple.developer.browser.app-installation": "Web browsers",

    # Wireless interfaces
    "com.apple.developer.networking.wifi-info": "Wireless interfaces",
    "com.apple.external-accessory.wireless-configuration": "Wireless interfaces",
    "com.apple.developer.networking.multipath": "Wireless interfaces",
    "com.apple.developer.networking.multicast": "Wireless interfaces",
    "com.apple.developer.networking.HotspotConfiguration": "Wireless interfaces",
    "com.apple.developer.nfc.readersession.formats": "Wireless interfaces",
    "com.apple.developer.nfc.hce": "Wireless interfaces",
    "com.apple.developer.nfc.hce.iso7816.select-identifier-prefixes": "Wireless interfaces",
    "com.apple.developer.nfc.hce.default-contactless-app": "Wireless interfaces",

    # BrowserEngineKit
    "com.apple.developer.embedded-web-browser-engine": "BrowserEngineKit",
    "com.apple.developer.memory.transfer_accept": "BrowserEngineKit",
    "com.apple.developer.memory.transfer_send": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.host": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.networking": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.rendering": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.webcontent": "BrowserEngineKit",

    # ScreenCaptureKit
    "com.apple.developer.persistent-content-capture": "ScreenCaptureKit",
}


SECURITY_ENTITLEMENTS = {
    # Alternative Marketplaces
    "com.apple.developer.marketplace.app-installation": "Alternative Marketplaces",

    # Authentication
    "com.apple.developer.authentication-services.autofill-credential-provider": "Authentication",
    "com.apple.developer.applesignin": "Authentication",

    # Hypervisor
    "com.apple.security.hypervisor": "Hypervisor",
    "com.apple.vm.hypervisor": "Hypervisor",
    "com.apple.vm.device-access": "Hypervisor",
    "com.apple.vm.networking": "Hypervisor",
    "com.apple.security.virtualization": "Hypervisor",

    # iCloud
    "com.apple.developer.icloud-container-development-container-identifiers": "iCloud",
    "com.apple.developer.icloud-container-environment": "iCloud",
    "com.apple.developer.icloud-container-identifiers": "iCloud",
    "com.apple.developer.icloud-services": "iCloud",
    # "com.apple.developer.ubiquity-kvstore-identifier": "iCloud",
    "com.apple.private.icloud-account-access": "iCloud",

    # Networking
    "com.apple.developer.networking.networkextension": "Networking",
    "com.apple.developer.networking.vpn.api": "Networking",
    "com.apple.developer.associated-domains": "Networking",
    "com.apple.developer.associated-domains.applinks.read-write": "Networking",
    "com.apple.developer.networking.manage-thread-network-credentials": "Networking",
    "com.apple.developer.networking.slicing.appcategory": "Networking",
    "com.apple.developer.networking.slicing.trafficcategory": "Networking",
    "com.apple.developer.networking.vmnet": "Networking",

    # Notifications
    "aps-environment": "Notifications",
    "com.apple.developer.aps-environment": "Notifications",
    "com.apple.developer.usernotifications.filtering": "Notifications",
    "com.apple.developer.usernotifications.time-sensitive": "Notifications",

    # Privacy
    "com.apple.developer.device-information.user-assigned-device-name": "Privacy",

    # App Sandbox
    "com.apple.security.app-sandbox": "App Sandbox",

    # App Sandbox Entitlements - Network
    "com.apple.security.network.client": "App Sandbox - Network",
    "com.apple.security.network.server": "App Sandbox - Network",
    
    # App Sandbox Entitlements - Hardware
    "com.apple.security.device.camera": "App Sandbox - Hardware",
    "com.apple.security.device.microphone": "App Sandbox - Hardware",
    "com.apple.security.device.usb": "App Sandbox - Hardware",
    "com.apple.security.device.print": "App Sandbox - Hardware",
    "com.apple.security.device.bluetooth": "App Sandbox - Hardware",
    "com.apple.security.device.audio-input": "App Sandbox - Hardware",

    # App Sandbox Entitlements - Address Book
    "com.apple.security.personal-information.addressbook": "App Sandbox - Address Book",

    # App Sandbox Entitlements - Location
    "com.apple.security.personal-information.location": "App Sandbox - Location",

    # App Sandbox Entitlements - Calendars
    "com.apple.security.personal-information.calendars": "App Sandbox - Calendars",

    # App Sandbox Entitlements - File Access
    "com.apple.security.files.user-selected.read-only": "App Sandbox - File Access",
    "com.apple.security.files.user-selected.read-write": "App Sandbox - File Access",
    "com.apple.security.files.downloads.read-only": "App Sandbox - File Access",
    "com.apple.security.files.downloads.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.pictures.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.pictures.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.music.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.music.read-write": "App Sandbox - File Access",
    "com.apple.security.assets.movies.read-only": "App Sandbox - File Access",
    "com.apple.security.assets.movies.read-write": "App Sandbox - File Access",
    "com.apple.security.files.all": "App Sandbox - File Access",
    
    # App Sandbox Entitlements - Accessibility
    "com.apple.security.accessibility": "App Sandbox - Accessibility",
    
    # Hardened Runtime
    "com.apple.security.cs.allow-jit": "Hardened Runtime",
    "com.apple.security.cs.allow-unsigned-executable-memory": "Hardened Runtime",
    "com.apple.security.cs.allow-dyld-environment-variables": "Hardened Runtime",
    "com.apple.security.cs.disable-library-validation": "Hardened Runtime",
    "com.apple.security.cs.disable-executable-page-protection": "Hardened Runtime",
    "com.apple.security.cs.debugger": "Hardened Runtime",
    # "com.apple.developer.kernel.extended-attribute-retrieval": "Hardenend Runtime",
    
    # App Groups Entitlement
    "com.apple.security.application-groups": "App Groups Entitlement",
    
    # Keychain Access Groups Entitlement
    "keychain-access-groups": "Keychain Access Groups Entitlement",
    
    # Data Protection Entitlement
    "com.apple.developer.default-data-protection": "Data Protection Entitlement",
    
    # App Attest Environment
    "com.apple.developer.devicecheck.appattest-environment": "App Attest Environment",

    # System Extensions - Endpoint Security
    "com.apple.developer.endpoint-security.client": "System Extensions - Endpoint Security",

    # Web browsers
    "com.apple.developer.web-browser": "Web browsers",
    "com.apple.developer.web-browser.public-key-credential": "Web browsers",
    "com.apple.developer.browser.app-installation": "Web browsers",

    # BrowserEngineKit
    "com.apple.developer.embedded-web-browser-engine": "BrowserEngineKit",
    "com.apple.developer.memory.transfer_accept": "BrowserEngineKit",
    "com.apple.developer.memory.transfer_send": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.host": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.networking": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.rendering": "BrowserEngineKit",
    "com.apple.developer.web-browser-engine.webcontent": "BrowserEngineKit",
}


ENTITLEMENTS_FEATURES = [
    # SECURITY-RELATED ENTITLEMENTS
    # Hardened Runtime
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.debugger",
    # App Sandbox
    "com.apple.security.app-sandbox",
    "com.apple.security.network.client",
    "com.apple.security.network.server",
    "com.apple.security.device.camera",
    "com.apple.security.device.microphone",
    "com.apple.security.device.usb",
    "com.apple.security.device.print",
    "com.apple.security.device.bluetooth",
    "com.apple.security.device.audio-input",
    "com.apple.security.personal-information.addressbook",
    "com.apple.security.personal-information.location",
    "com.apple.security.personal-information.calendars",
    "com.apple.security.files.user-selected.read-only",
    "com.apple.security.files.user-selected.read-write",
    "com.apple.security.files.downloads.read-only",
    "com.apple.security.files.downloads.read-write",
    "com.apple.security.assets.pictures.read-only",
    "com.apple.security.assets.pictures.read-write",
    "com.apple.security.assets.music.read-only",
    "com.apple.security.assets.music.read-write",
    "com.apple.security.assets.movies.read-only",
    "com.apple.security.assets.movies.read-write",
    "com.apple.security.files.all",
    "com.apple.security.accessibility",
    # Hypervisor
    "com.apple.security.hypervisor",
    "com.apple.vm.hypervisor",
    "com.apple.vm.device-access",
    "com.apple.vm.networking",
    "com.apple.security.virtualization",
    # Authentication
    "com.apple.developer.authentication-services.autofill-credential-provider",
    "com.apple.developer.applesignin",
    # iCloud
    "com.apple.developer.icloud-container-development-container-identifiers",
    "com.apple.developer.icloud-container-environment",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.icloud-services",
    "com.apple.private.icloud-account-access",
    # Entitlements based on https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements
    "com.apple.rootless.install",
    "com.apple.system-task-ports",
    "com.apple.security.get-task-allow",
    "com.apple.private.tcc.manager",
    "com.apple.rootless.storage.TCC",
    "system.install.apple-software",
    "system.install.apple-software.standard-user",
    "com.apple.private.security.kext-management",
    # Other entitlements based on those found in the dataset
    "com.apple.application-identifier",
    "com.apple.security.automation.apple-events",
    "com.apple.developer.team-identifier",
    "com.apple.security.temporary-exception.mach-lookup.global-name",
    "com.apple.security.temporary-exception.files.absolute-path.read-only",
    "com.apple.security.personal-information.photos-library",
    "com.apple.security.inherit",
    "com.apple.security.files.bookmarks.app-scope",
    "platform-application",
    "com.apple.private.tcc.allow",
    "com.apple.security.print",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.security.temporary-exception.apple-events",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.security.exception.files.absolute-path.read-write",
    "com.apple.security.iokit-user-client-class",
    "com.apple.private.accounts.allaccounts",
    "com.apple.security.temporary-exception.files.home-relative-path.read-write",
    "com.apple.private.security.no-sandbox",
    "com.apple.private.persona-mgmt",
    "com.apple.private.coreservices.canmaplsdatabase",
    # Entitlements specific for malware
    "task_for_pid-allow",
    "com.apple.private.security.no-container",
    "com.apple.developer.networking.wifi-info",
    "com.apple.UIKit.status-bar-override-allow",
    "com.apple.private.security.container-manager",
    "com.apple.lsapplicationworkspace.rebuildappdatabases",
    "com.apple.private.MobileContainerManager.allowed",
    "run-unsigned-code",
    "com.apple.developer.healthkit.access",
    "com.apple.private.security.storage.MobileDocuments",
    "com.apple.private.MobileInstallationHelperService.allowed",
    "com.apple.private.MobileInstallationHelperService.InstallDaemonOpsEnabled",
    "com.apple.private.uninstall.deletion",
    "com.apple.private.WebClips.read-write",
    "com.apple.developer.healthkit",
    "com.apple.locationd.simulation",
    "com.apple.private.mobileinstall.allowedSPI",
]


ENTITLEMENTS_FEATURES_FINAL = [
    "ent_security.cs.allow-jit",
    "ent_security.cs.allow-unsigned-executable-memory",
    "ent_security.cs.allow-dyld-environment-variables",
    "ent_security.cs.disable-library-validation",
    "ent_security.cs.disable-executable-page-protection",
    "ent_security.cs.debugger",
    "ent_security.app-sandbox",
    "ent_security.network.client",
    "ent_security.network.server",
    "ent_security.device.camera",
    "ent_security.device.microphone",
    "ent_security.device.usb",
    "ent_security.device.print",
    "ent_security.device.bluetooth",
    "ent_security.device.audio-input",
    "ent_security.personal-information.addressbook",
    "ent_security.personal-information.location",
    "ent_security.personal-information.calendars",
    "ent_security.files.user-selected.read-only",
    "ent_security.files.user-selected.read-write",
    "ent_security.files.downloads.read-only",
    "ent_security.files.downloads.read-write",
    "ent_security.assets.pictures.read-only",
    "ent_security.assets.pictures.read-write",
    "ent_security.assets.music.read-only",
    "ent_security.assets.music.read-write",
    "ent_security.assets.movies.read-only",
    "ent_security.assets.movies.read-write",
    "ent_security.files.all",
    "ent_security.accessibility",
    "ent_security.hypervisor",
    "ent_vm.hypervisor",
    "ent_vm.device-access",
    "ent_vm.networking",
    "ent_security.virtualization",
    "ent_developer.authentication-services.autofill-credential-provider",
    "ent_developer.applesignin",
    "ent_developer.icloud-container-development-container-identifiers",
    "ent_developer.icloud-container-environment",
    "ent_developer.icloud-container-identifiers",
    "ent_developer.icloud-services",
    "ent_private.icloud-account-access",
    "ent_generic.rootless.install",
    "ent_generic.system-task-ports",
    "ent_security.get-task-allow",
    "ent_private.tcc.manager",
    "ent_generic.rootless.storage.TCC",
    "ent_system.install.apple-software",
    "ent_system.install.apple-software.standard-user",
    "ent_private.security.kext-management",
    # NEW ENTITLEMENTS
    "ent_generic.application-identifier",
    "ent_security.automation.apple-events",
    "ent_developer.team-identifier",
    "ent_private.tcc.allow",
    "ent_run-unsigned-code",
]


ENTITLEMENTS_FEATURES_ALL = [
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.app-sandbox",
    "com.apple.security.get-task-allow",
    "com.apple.application-identifier",
    "com.apple.security.application-groups",
    "com.apple.security.network.client",
    "com.apple.security.device.audio-input",
    "com.apple.security.files.user-selected.read-write",
    "com.apple.security.device.camera",
    "com.apple.security.automation.apple-events",
    "com.apple.developer.team-identifier",
    "com.apple.security.cs.debugger",
    "com.apple.security.files.user-selected.read-only",
    "com.apple.security.cs.disable-executable-page-protection",
    "keychain-access-groups",
    "com.apple.security.network.server",
    "com.apple.security.personal-information.location",
    "com.apple.developer.aps-environment",
    "com.apple.security.temporary-exception.mach-lookup.global-name",
    "com.apple.security.device.usb",
    "com.apple.security.personal-information.addressbook",
    "com.apple.security.device.bluetooth",
    "com.apple.security.device.microphone",
    "com.apple.security.temporary-exception.files.absolute-path.read-only",
    "com.apple.security.personal-information.calendars",
    "com.apple.security.personal-information.photos-library",
    "com.apple.security.device.print",
    "com.apple.developer.icloud-services",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.security.inherit",
    "com.apple.security.files.bookmarks.app-scope",
    "com.apple.developer.icloud-container-environment",
    "platform-application",
    "com.apple.private.tcc.allow",
    "com.apple.security.print",
    "com.apple.security.files.downloads.read-write",
    "com.apple.developer.associated-domains",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.security.temporary-exception.apple-events",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.security.exception.files.absolute-path.read-write",
    "com.apple.security.iokit-user-client-class",
    "com.apple.private.accounts.allaccounts",
    "com.apple.security.temporary-exception.files.home-relative-path.read-write",
    "com.apple.private.security.no-sandbox",
    "com.apple.private.persona-mgmt",
    "com.apple.private.coreservices.canmaplsdatabase",
    "task_for_pid-allow",
    "com.apple.developer.healthkit",
    "com.apple.private.security.no-container",
    "com.apple.security.temporary-exception.shared-preference.read-only",
    "com.apple.security.exception.mach-lookup.global-name",
    "com.apple.managedconfiguration.profiled-access",
    "com.apple.security.temporary-exception.shared-preference.read-write",
    "com.apple.private.security.restricted-application-groups",
    "com.apple.developer.networking.networkextension",
    "com.apple.private.security.system-application",
    "com.apple.SystemConfiguration.SCDynamicStore-write-access",
    "com.apple.developer.siri",
    "com.apple.private.security.container-required",
    "com.apple.mobile.deleted.AllowFreeSpace",
    "com.apple.security.files.bookmarks.document-scope",
    "com.apple.security.temporary-exception.sbpl",
    "com.apple.developer.networking.wifi-info",
    "com.apple.UIKit.status-bar-override-allow",
    "com.apple.springboard.launchapplications",
    "com.apple.developer.icloud-container-development-container-identifiers",
    "com.apple.private.security.container-manager",
    "com.apple.lsapplicationworkspace.rebuildappdatabases",
    "com.apple.private.MobileContainerManager.allowed",
    "com.apple.security.assets.pictures.read-only",
    "com.apple.private.MobileGestalt.AllowedProtectedKeys",
    "run-unsigned-code",
    "com.apple.developer.healthkit.access",
    "com.apple.private.aps-connection-initiate",
    "com.apple.security.assets.music.read-only",
    "com.apple.springboard.opensensitiveurl",
    "com.apple.private.security.storage.MobileDocuments",
    "com.apple.security.assets.movies.read-only",
    "com.apple.locationd.effective_bundle",
    "com.apple.security.scripting-targets",
    "com.apple.private.MobileInstallationHelperService.InstallDaemonOpsEnabled",
    "com.apple.private.uninstall.deletion",
    "com.apple.private.MobileInstallationHelperService.allowed",
    "com.apple.wifi.manager-access",
    "com.apple.CommCenter.fine-grained",
    "com.apple.security.temporary-exception.files.home-relative-path.read-only",
    "com.apple.itunesstored.private",
    "com.apple.developer.pass-type-identifiers",
    "com.apple.developer.homekit",
    "com.apple.security.temporary-exception.files.absolute-path.read-write",
    "com.apple.private.cloudkit.spi",
    "com.apple.security.exception.shared-preference.read-write",
    "com.apple.private.network.socket-delegate",
    "com.apple.locationd.simulation",
    "com.apple.private.WebClips.read-write",
    "fairplay-client",
    "com.apple.security.assets.pictures.read-write",
    "com.apple.private.assets.accessible-asset-types",
    "com.apple.private.corerecents",
    "com.apple.developer.applesignin",
    "com.apple.private.communicationsfilter",
    "com.apple.private.ids.messaging",
    "com.apple.developer.system-extension.install",
    "com.apple.CoreRoutine.LocationOfInterest",
    "com.apple.private.mobileinstall.allowedSPI",
    "com.apple.developer.networking.vpn.api",
    "com.apple.icloud.fmfd.access",
    "com.apple.private.cloudkit.masquerade",
    "com.apple.SystemConfiguration.SCPreferences-write-access",
    "com.apple.private.appleaccount.app-hidden-from-icloud-settings",
    "com.apple.springboard.CFUserNotification",
    "com.apple.private.bmk.allow",
    "com.apple.system-task-ports",
    "com.apple.private.imcore.imremoteurlconnection",
    "com.apple.imagent",
    "com.apple.security.smartcard",
    "com.apple.locationd.authorizeapplications",
    "com.apple.private.hid.client.event-dispatch.internal",
    "com.apple.private.ind.client",
    "com.apple.keystore.device",
    "com.apple.private.skip-library-validation",
    "com.apple.accounts.appleaccount.fullaccess",
    "adi-client",
    "com.apple.private.networkextension.configuration",
    "com.apple.private.applemediaservices",
    "com.apple.security.assets.music.read-write",
    "com.apple.timed",
    "com.apple.homekit.private-spi-access",
    "com.apple.private.cloudkit.setEnvironment",
    "com.apple.security.exception.iokit-user-client-class",
    "com.apple.authkit.client.internal",
    "com.apple.BTServer.le",
    "com.apple.locationd.status",
    "proc_info-allow",
    "com.apple.springboard.debugapplications",
    "com.apple.companionappd.connect.allow",
    "com.apple.private.librarian.container-proxy",
    "com.apple.authkit.client.private",
    "backupd-connection-initiate",
    "com.apple.coremedia.allow-protected-content-playback",
    "com.apple.assistant.settings",
    "com.apple.private.iad.opt-in-control",
    "com.apple.private.healthkit",
    "com.apple.visualvoicemail.client",
    "com.apple.private.domain-extension",
    "com.apple.cards.all-access",
    "keychain-cloud-circle",
    "com.apple.backboardd.launchapplications",
    "com.apple.locationd.defaults_access",
    "com.apple.CoreRoutine.preferences",
    "dynamic-codesigning",
    "com.apple.coreduetd.allow",
    "com.apple.private.game-center",
    "com.apple.developer.maps",
    "com.apple.private.carkit",
    "com.apple.MobileInternetSharing.allow",
    "abs-client",
    "com.apple.keystore.stash.access",
    "com.apple.securebackupd.access",
    "com.apple.mediastream.mstreamd-access",
    "com.apple.multitasking.termination",
    "com.apple.private.security.storage.AppBundles",
    "com.apple.developer.driverkit",
    "com.apple.developer.default-data-protection",
    "com.apple.private.security.syspolicy.kext-management",
    "com.apple.seld.cm",
    "com.apple.networkd.set_account_identifier",
    "auth-key-vault-client",
    "com.apple.private.nlcd-control",
    "com.apple.locationd.usage_oracle",
    "com.apple.keystore.auth-token",
    "com.apple.private.social.facebook.token",
    "com.apple.passes.add-silently",
    "com.apple.private.lockdown.reset-pairing",
    "com.apple.aosnotification.aosnotifyd-access",
    "com.apple.nfcd.info",
    "com.apple.frontboard.shutdown",
    "com.apple.mobilemail.mailservices",
    "com.apple.private.game-center.bypass-authentication",
    "com.apple.private.webbookmarks.settings",
    "com.apple.ci",
    "com.apple.private.accounts.bundleidspoofing",
    "com.apple.private.sharing.unlock-manager",
    "com.apple.launchservices.clearadvertisingid",
    "com.apple.filesystem-metadata-snapshotting",
    "com.apple.private.cloudphotod.access",
    "com.apple.private.lockdown.finegrained-set",
    "com.apple.networkd.modify_settings",
    "com.apple.springboard.wipedevice",
    "com.apple.private.healthkit.authorization_manager",
    "com.apple.private.tcc.manager",
    "com.apple.ios.StoreKit.store-page",
    "com.apple.private.safari.cloudtabs",
    "com.apple.private.lockdown.finegrained-get",
    "com.apple.sh",
    "com.apple.private.hid.client.event-filter",
    "com.apple.private.safari.offlinereadinglist",
    "com.apple.asl.access_as_root",
    "com.apple.BTServer.programmaticPairing",
    "com.apple.nanobackup",
    "com.apple.awdd.manager-access",
    "com.apple.remotenotification.preferences",
    "com.apple.nvram.boot-args-set-allow",
    "com.apple.tzlink.allow",
    "com.apple.private.hid.manager.client",
    "com.apple.private.timezoneupdates.tzd.access",
    "com.apple.springboard.iconState",
    "com.apple.bulletinboard.settings",
    "com.apple.backboard.displaybrightness",
    "com.apple.security.exception.files.home-relative-path.read-write",
    "com.apple.security.assets.movies.read-write",
    "com.apple.private.iokit.system-nvram-allow",
    "com.apple.private.security.kext-management",
    "com.apple.system-task-ports.control",
    "com.apple.private.security.storage-exempt.heritable",
    "com.apple.system-task-ports.token.control",
    "com.apple.security.files.user-selected.executable",
    "com.apple.private.CoreAuthentication.SPI",
    "com.apple.private.vfs.snapshot",
    "com.apple.developer.networking.custom-protocol",
    "com.apple.private.security.disk-device-access",
    "com.apple.developer.driverkit.builtin",
    "com.apple.private.spawn-driver",
    "com.apple.developer.driverkit.transport.pci",
    "com.apple.developer.driverkit.transport.pci.offloadEngineDisable",
    "com.apple.private.security.kext-collection-management",
    "com.apple.Contacts.database-allow",
    "com.apple.developer.auto-elect-plugin",
    "com.apple.developer.usernotifications.time-sensitive",
    "com.apple.private.corespotlight.internal",
    "com.apple.telephonyutilities.callservicesd",
    "com.apple.security.exception.shared-preference.read-only",
    "com.apple.developer.nfc.readersession.formats",
    "com.apple.developer.networking.HotspotConfiguration",
    "com.apple.private.swc.system-app",
    "com.apple.developer.usernotifications.communication",
    "inter-app-audio",
    "com.apple.private.suggestions.contacts",
    "com.apple.private.sociallayer.highlights",
    "com.apple.private.kernel.get-kext-info",
    "com.apple.private.apfs.revert-to-snapshot",
    "com.apple.private.cloudkit.systemService",
    "com.apple.coreduetd.people",
    "com.apple.private.contactsui",
    "com.apple.developer.networking.multipath",
    "com.apple.developer.healthkit.background-delivery",
    "com.apple.private.security.system-mount-authority",
    "com.apple.private.spawn-subsystem-root",
    "com.apple.private.kernel.system-override",
    "com.apple.private.contacts",
    "com.apple.private.kernel.override-cpumon",
    "com.apple.developer.ClassKit-environment",
    "com.apple.system-task-ports.read",
    "com.apple.external-accessory.wireless-configuration",
    "com.apple.developer.authentication-services.autofill-credential-provider",
    "com.apple.security.exception.files.home-relative-path.read-only",
    "com.apple.security.exception.files.absolute-path.read-only",
    "com.apple.private.rtcreportingd",
    "com.apple.private.iaaccounts",
    "com.apple.private.apfs.trim-active-file",
    "com.apple.rootless.storage.ane_model_cache",
    "com.apple.rootless.storage.triald",
    "com.apple.bluetooth.system",
    "com.apple.frontboard.launchapplications",
    "com.apple.private.security.storage.AppDataContainers",
    "com.apple.rootless.storage.MobileStorageMounter",
    "com.apple.private.ANEStorageMaintainer.allow",
    "com.apple.private.suggestions",
    "com.apple.developer.game-center",
    "com.apple.chronoservices",
    "com.apple.private.coreservices.canopenactivity",
    "com.apple.avfoundation.allow-system-wide-context",
    "com.apple.private.iosurfaceinfo",
    "com.apple.developer.endpoint-security.client",
    "com.apple.private.memorystatus",
    "com.apple.private.iowatchdog.user-access",
    "com.apple.private.security.storage.SystemExtensionManagement",
    "com.apple.rootless.volume.Update",
    "com.apple.mediaanalysisd.client",
    "com.apple.private.canGetAppLinkInfo",
    "com.apple.private.cloudkit.serviceNameForContainerMap",
    "com.apple.chrono.open-urls-direct",
    "com.apple.private.tcc.allow-prompting",
    "com.apple.icloud.findmydeviced.access",
    "com.apple.chrono.invalidate-timelines",
    "com.apple.private.security.clear-library-validation",
    "com.apple.private.tcc.manager.check-by-audit-token",
    "com.apple.private.attribution.implicitly-assumed-identity",
    "com.apple.intents.extension.discovery",
    "com.apple.sharing.Client",
    "com.apple.security.system-groups",
    "com.apple.mobileactivationd.spi",
    "com.apple.keystore.sik.access",
    "com.apple.private.mobileinstall.xpc-services-enabled",
    "com.apple.private.fpsd.client",
    "com.apple.system-task-ports.read.safe",
    "com.apple.private.diskimages.kext.user-client-access",
    "com.apple.private.ubiquity-additional-kvstore-identifiers",
    "com.apple.avfoundation.allows-access-to-device-list",
    "com.apple.avfoundation.allows-set-output-device",
    "com.apple.rootless.volume.Preboot",
    "com.apple.rootless.datavault.metadata",
    "com.apple.private.ids.idquery-cache",
    "com.apple.private.screen-time",
    "com.apple.private.screentime-communication",
    "com.apple.security.files.downloads.read-only",
    "com.apple.private.MobileContainerManager.lookup",
    "com.apple.coreduetd.context",
    "com.apple.icloud.searchpartyd.beaconmanager",
    "com.apple.icloud.searchpartyd.ownersession",
    "com.apple.proactive.eventtracker",
    "com.apple.private.applecredentialmanager.allow",
    "com.apple.private.security.storage.Notes",
    "com.apple.private.dt.instruments.dtservicehub.client",
    "com.apple.private.security.storage.Mail",
    "com.apple.rootless.storage.remotemanagementd",
    "com.apple.private.dmd.emergency-mode",
    "com.apple.private.dmd.policy",
    "com.apple.private.photos.service.internal.cloud",
    "com.apple.private.tcc.manager.access.modify",
    "com.apple.security.temporary-exception.apple-events:before:10.8",
    "com.apple.developer.device-information.user-assigned-device-name",
    "com.apple.security.temporary-exception.iokit-user-client-class",
    "com.apple.private.canModifyAppLinkPermissions",
    "com.apple.developer.web-browser.public-key-credential",
    "com.apple.private.swc.additional-service-details-consumer",
    "com.apple.amp.library.client",
    "com.apple.private.cloudkit.customAccounts",
    "com.apple.private.tcc.manager.access.read",
    "com.apple.private.hsa-authentication-processing",
    "com.apple.private.security.storage.FindMy",
    "com.apple.rootless.internal-installer-equivalent",
    "com.apple.security.temporary-exception.mach-register.global-name",
    "com.apple.payment.card-on-file",
    "com.apple.private.biome.writer",
    "com.apple.security.temporary-exception.audio-unit-host",
    "com.apple.private.AuthorizationServices",
    "com.apple.keystore.filevault",
    "com.apple.private.tcc.allow.overridable",
    "com.apple.private.xpc.launchd.userspace-reboot",
    "com.apple.hid.system.user-access-service",
    "com.apple.developer.weatherkit",
    "com.apple.developer.usersafety.client",
    "com.apple.private.biome.read-write",
    "com.apple.private.clouddocs.sharing-proxy",
    "com.apple.findmy.findmylocate.locationservice",
    "com.apple.private.ids.identityservicesd",
    "com.apple.findmy.findmylocate.settings",
    "com.apple.private.ids.idsquery",
    "com.apple.findmy.findmylocate.friendshipservice",
    "com.apple.private.managed-settings.effective-read",
    "com.apple.usersafety.service",
    "com.apple.security.files.all",
    "com.apple.security.ldt-in-64bit-process",
    "com.apple.private.security.storage.Weather",
    "com.apple.private.appstored",
    "com.apple.private.applesmc.user-access",
    "com.apple.private.remindd",
    "com.apple.private.tcc.manager.access.delete",
    "com.apple.icloud.FindMyDevice.FindMyDeviceHelperXPCService.access",
    "com.apple.security.exception.files.absolute",
    "com.apple.icloud.searchpartyd.accessorydiscovery",
    "com.apple.icloud.searchpartyd.securelocations.access",
    "com.apple.intents.uiextension.discovery",
    "com.apple.icloud.searchpartyd.securelocations",
    "com.apple.security.attestation.access",
    "com.apple.CompanionLink",
    "com.apple.coretelephony.Identity.get",
    "com.apple.locationd.activity",
    "com.apple.private.photos.service.internal.library",
    "com.apple.photos.bourgeoisie",
    "com.apple.private.tcc.allow-or-regional-prompt",
    "com.apple.rootless.storage.coreduet_knowledge_store",
    "com.apple.videoconference.allow-conferencing",
    "com.apple.shortcuts.background-running",
    "com.apple.private.security.storage.HomeKit",
    "com.apple.developer.group-session",
    "com.apple.private.audio.notification-wake-audio",
    "com.apple.private.octagon",
    "com.apple.private.pmap.load-trust-cache",
    "com.apple.FaceTime.NoPrompt",
    "com.apple.private.admin.writeconfig",
    "com.apple.private.security.bootpolicy",
    "com.apple.private.CallHistory.read-write",
    "com.apple.private.pluginkit.persona",
    "com.apple.rootless.restricted-block-devices",
    "com.apple.rootless.storage.shortcuts",
    "com.apple.private.vfs.allow-low-space-writes",
    "com.apple.private.set-atm-diagnostic-flag",
    "com.apple.private.allow-explicit-graphics-priority",
    "com.apple.private.usbdevice.setdescription",
    "com.apple.private.email",
    "com.apple.private.attribution.usage-reporting-only.implicitly-assumed-identity",
    "com.apple.private.interstellar.data-access",
    "com.apple.private.clouddocs.sharing.private-interface",
    "com.apple.BTServer.allowRestrictedServices",
    "com.apple.launchservices.receivereferrerrurl",
    "com.apple.payment.amp-card-enrollment",
    "com.apple.private.notificationcenter-system",
    "com.apple.symptom_analytics.query",
    "com.apple.private.appstorecomponents",
    "com.apple.private.familycircle",
    "com.apple.private.gpuwrangler",
    "com.apple.wlan.authentication",
    "com.apple.private.logging.diagnostic",
    "com.apple.private.diskmanagement.set-boot-device",
    "com.apple.security.ts.tmpdir",
    "com.apple.private.ZhuGeSupport.CopyValue",
    "com.apple.tailspin.dump-output",
    "com.apple.private.sandbox.profile:embedded",
    "com.apple.private.bookkit",
    "com.apple.mediaremote.send-commands",
    "com.apple.springboard.shortcutitems.customimage",
    "com.apple.mediaremote.set-playback-state",
    "com.apple.private.cfnetwork.har-capture-amp",
    "com.apple.private.hid.client.event-monitor",
    "com.apple.security.exception.process-info",
    "com.apple.QuartzCore.secure-mode",
    "com.apple.developer.sensitivecontentanalysis.client",
    "com.apple.sensitivecontentanalysis.service",
    "com.apple.PairingManager.Read",
    "com.apple.CoreRoutine.Application",
    "com.apple.coreaudio.register-internal-aus",
    "com.apple.private.ids.session",
    "com.apple.Settings.extension.host",
    "com.apple.private.ids.registration",
    "com.apple.private.iosmac.unscaled",
    "com.apple.siri.koa.donate.internal",
    "com.apple.private.calendar.has-adopted-modern-request-access-methods",
    "com.apple.private.corespotlight.search.internal",
    "com.apple.private.photoanalysisd.access",
    "com.apple.private.imcore.imdpersistence.database-access",
    "com.apple.private.imcore.spi.database-access",
    "com.apple.private.stackshot",
    "com.apple.private.IASInstallerAuthAgent",
    "com.apple.private.security.storage.CallHistory",
    "com.apple.private.aps-client-cert-access",
    "com.apple.coretelephony.Calls.allow",
    "com.apple.security.device.serial",
    "com.apple.UIKit.vends-view-services",
    "com.apple.private.security.storage.Messages",
    "com.apple.authorization.extract-password",
    "com.apple.private.network.statistics",
    "com.apple.private.xpc.persona-creator",
    "com.apple.keystore.access-keychain-keys",
    "com.apple.private.security.storage.driverkitd",
    "com.apple.private.record_system_event",
    "com.apple.apfs.get-dev-by-role",
    "com.apple.private.vfs.pivot-root",
    "com.apple.private.amfi.can-allow-non-platform",
    "com.apple.private.roots-installed-read-write",
    "com.apple.rootless.storage.early_boot_mount",
    "com.apple.private.spawn-panic-crash-behavior",
    "com.apple.private.vfs.graftdmg",
    "com.apple.private.security.storage.launchd",
    "com.apple.private.sociallayer.collaboration-handshake",
    "com.apple.private.cloudkit.oopui",
    "com.apple.private.clouddocs.folder-sharing-proxy",
    "com.apple.sharesheet.recipients",
    "com.apple.private.viewbridge.window.child.transparent",
    "com.apple.developer.storage.fileutil",
    "com.apple.BTServer.le.att",
    "com.apple.private.photos.cpanalytics.allow",
    "com.apple.DiagnosticExtensions.extension",
    "com.apple.symptoms.NetworkOfInterest",
    "com.apple.private.commerce",
    "com.apple.private.AmbientDisplay.messaging",
    "com.apple.wifi.events",
    "com.apple.private.coreservices.cangetcurrentactivityinfo",
    "com.apple.usermanagerd.persona.fetch",
    "com.apple.security.enterprise-volume-access",
    "com.apple.private.copresence",
    "com.apple.private.metadata.exattrs",
    "com.apple.private.xpc.role-account",
    "com.apple.private.nsurlsession.impersonate",
    "com.apple.springboard.remote-alert",
    "com.apple.bulletinboard.observer",
    "com.apple.hid.manager.user-access-device",
    "com.apple.private.usernotifications.bundle-identifiers",
    "com.apple.networkrelay.devices.read",
    "com.apple.frontboardservices.display-layout-monitor",
    "com.apple.springboard.statusbarstyleoverrides",
    "com.apple.private.biome.client-identifier",
    "com.apple.private.system-keychain",
    "com.apple.excludes-extensions",
    "com.apple.private.biome.read-only",
    "com.apple.private.appshortcuts-allow-omit-appname",
    "com.apple.private.mobileinstall.upgrade-enabled",
    "com.apple.private.iad.news-client",
    "com.apple.private.photos.service.debug",
    "com.apple.private.photos.service.mediaconversion",
    "com.apple.private.persona.read",
    "com.apple.mediaremote.device-info",
    "com.apple.private.homekit.person-manager",
    "com.apple.runningboard.launchprocess",
    "com.apple.mediaremote.remote-control-discovery",
    "com.apple.private.homeenergy",
    "com.apple.accounts.appleidauthentication.defaultaccess",
    "com.apple.accounts.inactive.fullaccess",
    "com.apple.extensionkit.host.extension-point-identifiers",
    "com.apple.springboard.hardware-button-service.event-consumption",
    "com.apple.private.security.storage.MessagesMetaData",
    "com.apple.springboard-ui.client",
    "com.apple.private.homekit.wallet-key",
    "com.apple.private.security.storage.Home",
    "com.apple.nfcd.session.reader.internal",
    "com.apple.sharing.DeviceDiscovery",
    "com.apple.nano.nanoregistry.generalaccess",
    "com.apple.private.ids.session-private",
    "com.apple.private.homekit.diagnostics",
    "com.apple.assistant.dictation.prerecorded",
    "com.apple.itunescloud.in-app-message-service",
    "com.apple.private.associated-domains",
    "com.apple.private.xpc.domain-extension",
    "com.apple.private.storagekitd.destructive",
    "com.apple.private.exchangesyncd",
    "com.apple.private.ckks",
    "com.apple.spotlight.photos.entitledattributes",
    "seatbelt-profiles",
    "com.apple.private.CacheDelete",
    "com.apple.system.get-alert-tone",
    "com.apple.security.files.bookmarks.collection-scope",
    "com.apple.private.bootability",
    "com.apple.private.donotdisturb.state.request.client-identifiers",
    "com.apple.symptom_diagnostics.report",
    "com.apple.private.notificationcenterui.alerts",
    "com.apple.system.set-alert-tone",
    "com.apple.private.sociallayer.shareable-content",
    "com.apple.private.intents.extension",
    "com.apple.rootless.volume.iSCPreboot",
    "com.apple.private.stockholm.allow",
    "com.apple.private.logging.stream",
    "com.apple.private.AssetCacheServices.Manager",
    "com.apple.coreaudio.allow-amr-decode",
    "com.apple.systemstatus.publisher.domains",
    "com.apple.private.voicememod.client",
    "com.apple.sysmond.client",
    "com.apple.camera.iokit-user-access",
    "com.apple.private.photos.service.notification",
    "com.apple.private.security.storage.Photos",
    "com.apple.private.applesepmanager.allow",
    "com.apple.payment.all-access",
    "com.apple.rootless.storage.ConfigurationProfilesPrivate",
    "com.apple.private.configurationprofiles.readwrite",
    "com.apple.developer.usernotifications.filtering",
    "com.apple.private.in-app-payments",
    "com.apple.developer.user-fonts",
    "com.apple.private.xpc.service-configure",
    "com.apple.locationd.preauthorized",
    "com.apple.developer.devicecheck.appattest-environment",
    "com.apple.developer.healthkit.recalibrate-estimates",
    "beta-reports-active",
    "com.apple.private.cs.debugger",
    "research.com.apple.license-to-operate",
    "com.apple.private.messages.autoshare",
    "com.apple.private.addressBook.sharingItems",
    "com.apple.corerecents.recentsd",
    "com.apple.developer.driverkit.family.serial",
    "com.apple.private.corespotlight.bundleid",
    "com.apple.private.corewifi",
    "com.apple.DeviceAccess",
    "com.apple.developer.associated-domains.applinks.read-write",
    "com.apple.private.mobiletimerd",
    "com.apple.multitasking.unlimitedassertions",
    "com.apple.geoservices.setanydefault",
    "com.apple.private.iokit.batterydata",
    "com.apple.wifi.events.private",
    "com.apple.private.pluginkit.manager",
    "com.apple.private.security.storage.CloudDocsDB",
    "com.apple.private.librarian.can-get-application-info",
    "com.apple.private.foundation.filecoordination-debug",
    "com.apple.private.personas.propagate",
    "com.apple.private.security.storage.SystemKeychain",
    "com.apple.private.security.storage.SFAnalytics",
    "com.apple.private.cloudkit.realTimeOperations",
    "com.apple.security.restricted-application-groups",
    "com.apple.networking.ethernet.user-access",
    "com.apple.aned.private.allow",
    "com.apple.private.EnableMSSecBoot",
    "com.apple.private.diskmanagement.make-legacy-bootable",
    "com.apple.security.temporary-exception.files.home-relative-path.read-onlycom.apple.security.temporary-exception.files.home-relative-path.read-only",
    "com.apple.wifi.priority.internal",
    "com.apple.wifi.priority.id",
    "com.apple.bluetooth.control",
    "com.apple.BluetoothServices",
    "com.apple.tailspin.config-apply",
    "com.apple.nfcd.hwmanager",
    "com.apple.driver.AppleConvergedIPC.user-access",
    "com.apple.runningboard.process-state",
    "com.apple.private.security.storage.ExposureNotification",
    "com.apple.driver.AppleBluetoothModule.user-access",
    "com.apple.private.dprivacyd.allow",
    "com.apple.private.networkserviceproxy",
    "com.apple.springboard.allowallcallurls",
    "com.apple.private.security.storage.universalaccess",
    "com.apple.accounts.facebook.defaultaccess",
    "com.apple.iBooks.BDSService.private",
    "com.apple.ibooks.BLService.private",
    "com.apple.developer.carplay-audio",
    "com.apple.private.social.facebook.like",
    "com.apple.springboard.wallpaperAnimationSuspension",
    "com.apple.developer.usernotifications.critical-alerts",
    "com.apple.springboard.allowIconVisibilityChanges",
    "com.apple.developer.contacts.notes",
    "com.apple.networkrelay.deviceMonitor",
    "com.apple.mobilemail",
    "com.apple.captive.private",
    "com.apple.coremedia.endpointremotecontrolsession.xpc",
    "com.apple.PairingManager.HomeKit",
    "com.apple.coreaudio.CanRecordPastData",
    "CARCapableApp",
    "com.apple.private.seeding.client",
    "com.apple.private.ids.self-session",
    "com.apple.private.coordination.alarms",
    "com.apple.private.corewifi.readonly",
    "com.apple.HomePlatformSettingsUI.CarrySettings",
    "com.apple.sharing.Session",
    "com.apple.coreaudio.CanRecordWithoutSessionActivation",
    "com.apple.voicetrigger.voicetriggerservice",
    "com.apple.mediasetupd.client",
    "com.apple.private.coordination.timers",
    "com.apple.soundscapes.picker",
    "com.apple.managedconfiguration.profiled.configurationprofiles",
    "com.apple.private.homekit.shortcuts-automation-access",
    "com.apple.multitasking.systemappassertions",
    "com.apple.private.homekit.cameraclips",
    "com.apple.wifi.eap-nearby-device-setup-config-copy",
    "CARAppHidden",
    "com.apple.networkrelay.devices.write",
    "com.apple.mkb.usersession.info",
    "com.apple.runningboard.terminateprocess",
    "com.apple.private.securityd.stash",
    "com.apple.private.OAHSoftwareUpdate",
    "com.apple.private.system_installd.connection",
    "com.apple.private.security.storage.mobilesync.heritable",
    "com.apple.mediaremote.allow",
    "com.apple.private.sqlite.sqlite-encryption",
    "com.apple.PairingManager.RemovePeer",
    "com.apple.amp.devices.client",
    "com.apple.cdp.recoverykey",
    "com.apple.amp.artwork.client",
    "com.apple.PairingManager.Write",
    "com.apple.private.security.storage.Stocks",
    "com.apple.private.calendar.allow-suggestions",
    "com.apple.private.mailservice.delivery",
    "com.apple.InstallerDiagnostics.PermittedClient",
    "com.apple.private.security.storage.PhotosLibraries",
    "com.apple.spotlight.documentunderstanding.entitledattributes",
    "com.apple.corespotlight.search.allowed.bundleIDs",
    "com.apple.private.security.syspolicy.package-installation",
    "com.apple.private.xpc.launchd.ios-system-session",
    "com.apple.private.mail.persistence",
    "com.apple.private.contacts.disable-remote-database-access",
    "com.apple.private.backupd.session",
    "com.apple.private.dark-wake-push",
    "com.apple.transparency.kt",
    "com.apple.private.imcore.imdpersistence.data-detection-access",
    "com.apple.private.ioaccelmemoryinfo",
    "com.apple.accounts.idms.fullaccess",
    "com.apple.springboard.openurlinbackground",
    "com.apple.siri.VoiceShortcuts.xpc",
    "com.apple.system-task-ports.inspect",
    "com.apple.security.temporary-exception.input-monitoring",
    "com.apple.security.personal-information.reminders",
    "com.apple.security.full-disk-access",
    "com.apple.developer.shared-with-you",
    "com.apple.trial.client",
    "com.apple.private.suggestions.reminders",
    "com.apple.private.ShazamKit",
    "com.apple.hid.manager.user-access-keyboard",
    "com.apple.private.corespeechd.activation",
    "com.apple.security.ts.mobile-keybag-access",
    "com.apple.private.donotdisturb.behavior.resolution.client-identifiers",
    "com.apple.siri.activation",
    "com.apple.DiagnosticExtensions.BluetoothHeadset",
    "com.apple.accessoryupdater.uarp",
    "com.apple.private.siri.activation",
    "com.apple.bluetooth.pairedInfoSecurity",
    "com.apple.corespeech.xpc",
    "com.apple.private.healthkit.source.default",
    "com.apple.private.corespeech.xpc",
    "com.apple.donotdisturb.service",
    "com.apple.accessories.transport.allowauth",
    "com.apple.siri.external_request",
    "com.apple.corespeechd.activation",
    "com.apple.pegasus.context",
    "com.apple.private.imagecapturecore.authorization_bypass",
    "com.apple.private.skylight.plugin-power",
    "com.apple.CallHistory.sync.allow",
    "com.apple.imagent.av",
    "com.apple.callhistory.pluginhelper",
    "com.apple.icloud.passwordreset",
    "com.apple.coreduetd.people.user",
    "com.apple.private.messages.collaboration-initiate-send",
    "com.apple.private.iokit.nvram-csr",
    "com.apple.rootless.volume.iSCRecovery",
    "com.apple.rootless.volume.Recovery",
    "com.apple.private.screencapture.allow",
    "com.apple.private.homekit.home-location",
    "com.apple.private.homekit.location",
    "com.apple.private.homekit.allow-secure-access",
    "com.apple.private.opendirectoryd.identity",
    "com.apple.keystore.console",
    "com.apple.security.virtualization",
    "com.apple.fileprovider.share",
    "com.apple.private.appintents-bundle-absolute-paths",
    "com.apple.private.donotdisturb.settings.modify.client-identifiers",
    "com.apple.private.donotdisturb.state.updates.client-identifiers",
    "com.apple.imagent.chat",
    "com.apple.private.appleevents.allowedtosend",
    "com.apple.private.opendirectoryd.auth-hint",
    "com.apple.private.sysdiagnose",
    "com.apple.private.followup",
    "com.apple.private.viewbridge.host.command-equivalent.attempt-at-will",
    "com.apple.private.extensionkit.host.unsandboxed-extensions-for-extension-points",
    "com.apple.private.photos.cpanalytics.cache.read",
    "com.apple.private.ids.messaging.urgent-priority",
    "com.apple.private.hid.client.service-protected",
    "com.apple.private.ac",
    "com.apple.private.network.management.data.development",
    "com.apple.private.photos.allowmemorymutation",
    "com.apple.proactive.PersonalizationPortrait.Topic.readOnly",
    "com.apple.coreidvd.spi",
    "com.apple.rootless.storage.AudioSettings",
    "com.apple.springboard.secureAppAssertion",
    "com.apple.locationd.place_inference",
    "com.apple.springboard.activateawayviewplugins",
    "com.apple.private.security.storage.ConfigurationProfilesPrivate",
    "com.apple.private.security.storage.preferences",
    "com.apple.private.MobileContainerManager.otherIdLookup",
    "com.apple.duet.activityscheduler.allow",
    "com.apple.private.security.storage.Safari",
    "com.apple.private.network.intcoproc.restricted.development",
    "com.apple.private.vfs.dataless-manipulation",
    "com.apple.private.amfi.version-restriction",
    "com.apple.private.xpc.launchd.event-monitor",
    "com.apple.mobileactivationd.device-identifiers",
    "com.apple.private.managedclient.mdmclient-needsauth-private",
    "com.apple.ManagedClient.cloudconfigurationd-access",
    "com.apple.private.logging.admin",
    "com.apple.trial.status.deployment-environment.allow",
    "com.apple.private.osanalytics.defaults.allow",
    "com.apple.private.roots-installed-read-only",
    "com.apple.watchlist.private",
    "com.apple.private.security.storage.News",
    "com.apple.private.xpc.launchd.userspace-reboot-now",
    "com.apple.locationd.private_info",
    "com.apple.locationd.configure",
    "com.apple.locationd.spectator",
    "com.apple.developer.networking.HotspotHelper",
    "com.apple.private.avfoundation.capture.nonstandard-client.allow",
    "com.apple.private.MobileGestalt.AllowProtectedKeys",
    "com.apple.bulletinboard.dataprovider",
    "com.apple.locationd.routine",
    "com.apple.basebandd.xpc.allow",
    "com.apple.private.mediaexperience.suppressrecordingstatetosystemstatus",
    "com.apple.CoreLocation.PrivateMode",
    "com.apple.wlan.userclient",
    "com.apple.developer.kernel.increased-memory-limit",
    "com.apple.developer.coremedia.hls.low-latency",
    "com.apple.private.corewifi.internal",
    "com.apple.private.airdrop.discovery",
    "com.apple.springboard.wallpaper-access",
    "com.apple.gasgauge.user-access-device",
    "com.apple.aop.rose.controller.admin",
    "com.apple.private.apfs.mount-root-writeable-at-shutdown",
    "com.apple.private.applepearl.allow",
    "com.apple.driver.AppleBasebandPCIControl.user-access",
    "com.apple.private.ProvInfoIOKitUserClient.access",
    "com.apple.driver.AppleConvergedIPCICEBBControl.user-access",
    "com.apple.iohideventsystem.server",
    "com.apple.private.gasgauge-update",
    "com.apple.private.applesse.allow",
    "com.apple.private.applemesa.allow",
    "com.apple.driver.AppleConvergedIPCICEBB.user-access",
    "com.apple.private.PurpleReverseProxy.allowed",
    "com.apple.security.system-group-containers",
    "com.apple.keystore.absinthe",
    "com.apple.keystore.fdr-access",
    "com.apple.private.IOAESAccelerator.fdr-key-handle",
    "com.apple.afu.userclientaccess",
    "com.apple.libFDR.AllowIdentifierOverride",
    "com.apple.keystore.obliterate-d-key",
    "com.apple.driver.AppleBasebandPCI.user-access",
    "com.apple.wifip2pd",
    "com.apple.private.network.management.control",
    "com.apple.private.network.management.data",
    "com.apple.private.network.reserved-port",
    "com.apple.private.ip-domain-table",
    "com.apple.BTServer.appleMfgDataAdvertising",
    "com.apple.BTServer.appleMfgDataScanner",
    "com.apple.private.snhelper",
    "com.apple.SystemConfiguration.trailing-edge-agent",
    "com.apple.private.network.awdl.restricted",
    "com.apple.private.necp.policies",
    "com.apple.private.network.delegation-whitelist",
    "com.apple.networkd_privileged",
    "com.apple.iokit.wakerequest",
    "com.apple.mDNSResponder_Helper",
    "com.apple.private.necp.match",
    "com.apple.symptom_analytics.delegate_symptom",
    "com.apple.private.SCNetworkConnection-proxy-user",
    "com.apple.private.validated-resolver",
    "com.apple.security.cs.debugger.read.root",
    "com.apple.developer.notificationcenter-identifiers",
    "com.apple.geoservices.map-subscriptions",
    "com.apple.private.appstoreagent",
    "com.apple.private.LocalAuthentication.DTO",
    "com.apple.private.LocalAuthentication.DTO.FallbackToNoAuth",
    "com.apple.private.commercekit.appstore",
    "com.apple.private.icloud-account-access",
    "com.apple.storekit.client-override",
    "com.apple.developer.driverkit.administrator",
    "com.apple.private.system_profiler.iBridgeDiscovery",
    "com.apple.private.responsibility.set-to-self.at-launch",
    "com.apple.private.clouddocs.can-publish-iwork-document",
    "com.apple.security.exception.ts.tmpdir",
    "com.apple.private.clouddocs.spi",
    "com.apple.private.diagnostics",
    "com.apple.private.cloudkit.protectiondata",
    "com.apple.private.cloudkit.packages",
    "com.apple.private.cloudkit.usePublicAPSToken",
    "com.apple.private.vfs.open-by-id",
    "com.apple.private.clouddocs.automation",
    "com.apple.private.clouddocs.can-grant-access-to-document",
    "com.apple.private.securityd.stash-agent-client",
    "com.apple.freeform.USD-renderer-remote-UI-entitlement",
    "com.apple.runningboard.freeform.USD-renderer-remote-UI",
    "com.apple.private.security.storage.network.heritable",
    "com.apple.private.apfs.create-synthetic-symlink-folder",
    "com.apple.wifi.scan",
    "com.apple.wifi.associate",
    "com.apple.private.mobilerepair.xpc",
    "com.apple.icloud.searchpartyd.access",
    "com.apple.private.tcc.manager.service-override.modify",
    "com.apple.private.iokit.nvram-bluetooth",
    "com.apple.private.timetool",
    "com.apple.BTServer.le.agent",
    "com.apple.searchparty.managedperipheral",
    "com.apple.icloud.searchpartyd.advertisementcache.access",
    "com.apple.rapport.Client",
    "com.apple.corecapture.manager-access",
    "com.apple.bluetooth.iokit-user-access",
    "com.apple.icloud.searchpartyd.finderstatemanager.access",
    "com.apple.bluetooth.user.services",
    "com.apple.private.carkit.carconnectiontime",
    "com.apple.networkrelay.xpcComm",
    "com.apple.nfcd.session.lpemConfig",
    "com.apple.private.dprivacyd.metadata.allow",
    "com.apple.private.externalaccessory.showallaccessories",
    "com.apple.powerui.smartcharging.AudioAccessory",
    "com.apple.icloud.searchpartyd.advertisementcache.write",
    "com.apple.BTServer.rawBytesAdvertise",
    "com.apple.private.appletamanager.allow",
    "com.apple.aop.fastpath.user-client",
    "com.apple.BTServer.pbap",
    "com.apple.private.trac.bridge.allow",
    "com.apple.springboard.smartCoverObserving",
    "com.apple.bulletinboard.utilities",
    "com.apple.private.iokit.powersource-control",
    "com.apple.private.keychain.sysbound",
    "com.apple.security.ts.springboard-services",
    "com.apple.bluetooth.internal",
    "com.apple.driver.BTDebug.user-access",
    "com.apple.aop.durant.user-client",
    "com.apple.locationd.synchronous",
    "com.apple.private.homekit",
    "com.apple.bluetoothaudiod",
    "com.apple.driver.AppleConvergedIPCControl.user-access",
    "com.apple.bluetooth.latencyCritical",
    "com.apple.private.skywalk.register-user-pipe",
    "com.apple.BTServer.avrcp",
    "com.apple.BTServer.map",
    "com.apple.developer.driverkit.userclient-access",
    "com.apple.aop.hid-device.user-client",
    "com.apple.private.accessibility.secureTap",
    "com.apple.private.accessibility.mayNeedBundleLoad",
    "com.apple.private.SkyLight.accessibility.ui",
    "com.apple.private.skylight.accessibility.pse",
    "com.apple.private.acccessibility.motionTrackingClient",
    "com.apple.private.accessibility.visuals",
    "com.apple.private.memoryinfo",
    "com.apple.private.accounts.customaccesssinfo",
    "com.apple.springboard.appbackgroundstyle",
    "com.apple.private.tipsd.discoverability",
    "com.apple.symptom_analytics",
    "com.apple.private.coreaudio.allow-aa-audiofile",
    "com.apple.SystemConfiguration.SCPreferences-read-access",
    "com.apple.private.data-usage-classification-override",
    "com.apple.QuartzCore.global-capture",
    "com.apple.springboard.topButtonFrames",
    "com.apple.private.imcore.imagent",
    "com.apple.runningboard.posterkit.host",
    "com.apple.private.security.storage.os_eligibility.readonly",
    "com.apple.PerfPowerServices.data-donation",
    "com.apple.mkb.usersession.keybagopaquedata",
    "com.apple.private.network.system-token-fetch",
    "com.apple.private.softwareupdated.OSUpdate",
    "com.apple.private.CoreAuthentication.BackgroundUI",
    "com.apple.private.suhelperd",
    "com.apple.private.softwareupdate.preferences",
    "com.apple.private.logout.forcecontinue",
    "com.apple.private.softwareupdate.postlogoutinstall",
    "com.apple.private.softwareupdate.disablescan",
    "com.apple.private.SoftwareUpdateNotificationManagerService",
    "com.apple.private.SoftwareUpdate.Client",
    "com.apple.private.opendirectoryd.ownership.read",
    "com.apple.softwareupdated.OSUpdate",
    "com.apple.coreaudio.untrackedSpatialization.allow",
    "com.apple.intelligentrouting.recommendationservice",
    "com.apple.itunescloud.quic.inprocess",
    "com.apple.notificationcenter.widgetcontrollerhascontent",
    "com.apple.ThunderboltEntitlement",
    "com.apple.private.ats.validation",
    "com.apple.XType.fontmover",
    "com.apple.ats",
    "com.apple.XType.fontmover.restore",
    "com.apple.private.apfs.set-firmlink",
    "com.apple.afk.user",
    "com.apple.private.cloudkit.explicitCodeOperationURL",
    "com.apple.private.coreservices.allowedToMatchUserActivities",
    "com.apple.private.paper.catalyst-scroll-event-forwarding",
    "com.apple.private.cloudkit.displaysSystemAcceptPrompt",
    "com.apple.private.copresence.stable-app-identifier",
    "com.apple.private.cloudkit.participant-pii",
    "com.apple.synapse.allowAddLinkContextRequests",
    "com.apple.pds.clientid",
    "com.apple.spotlight.search",
    "com.apple.private.system-extensions.tcc",
    "com.apple.private.contacts-avatar-picker-host",
    "com.apple.accounts.applicationidfrompid",
    "com.apple.coreduetd",
    "com.apple.private.persona.write",
    "com.apple.nearbyd.diagnostics",
    "com.apple.icloud.searchparty.ownersession.fmipitemaccess",
    "com.apple.icloud.searchpartyd.beaconsharing.access",
    "com.apple.nearbyd.xpc",
    "com.apple.icloud.searchpartyuseragent.pairingmanager",
    "com.apple.springboard.activateRemoteAlert",
    "com.apple.icloud.searchpartyd.pairingmanager",
    "com.apple.mkb.usersession.load",
    "com.apple.private.coreservices.canmanagebackgroundtasks",
    "com.apple.private.sharedfilelist.export",
    "com.apple.private.system-extensions.modify",
    "com.apple.private.smb.timemachine-control",
    "com.apple.asktod",
    "com.apple.private.trust-defaults-kvstore-identifier",
    "com.apple.private.mbsystemadministration",
    "com.apple.private.screencapturekit.sharingsessionsystemui",
    "com.apple.FTLivePhotoService",
    "com.apple.selectivesharing.system",
    "com.apple.security.lockdownmode.read",
    "com.apple.selectivesharing.session_system",
    "com.apple.imdpersistence.IMDPersistenceAgent-GroupMetadata",
    "com.apple.private.launchservices.changedefaulthandlers",
    "com.apple.private.iokit.darkwake-control",
    "com.apple.private.suggestions.urls",
    "com.apple.USBCEntitlement",
    "com.apple.shortcuts.droplet-creation",
    "com.apple.private.shared-with-you.on-screen-content",
    "com.apple.private.sociallayer.background-collaboration",
    "com.apple.developer.homekit.allow-setup-payload",
    "com.apple.idle-timer-services",
    "com.apple.developer.homekit.background-mode",
    "com.apple.seld.tsmmanager",
    "com.apple.internal.nfc.allow.backgrounded.session",
    "com.apple.private.hydrars",
    "com.apple.private.hydraresourcecoordinator.api-access",
    "com.apple.private.SkyLight.screencapturedirect",
    "com.apple.private.tcc.check-allow-on-responsible-process",
    "com.apple.private.coordination.role",
    "com.apple.private.coordination.messaging",
    "Application-Group",
    "com.apple.private.system-nfssvc",
    "com.apple.private.useractivity.sysdiagnose",
    "com.apple.private.AssetCacheServices.Tetherator",
    "com.apple.vm.networking",
    "com.apple.private.catalyst-openURL-source",
    "com.apple.private.stickers",
    "com.apple.appstored.install-apps",
    "com.apple.private.imcore.imtranscoderservice",
    "com.apple.remindd",
    "com.apple.private.donotdisturb.modeconfiguration.availability.client-identifiers",
    "com.apple.private.donotdisturb.settings.request.client-identifiers",
    "com.apple.private.suggestions.messages",
    "com.apple.StatusKit.publish.types",
    "com.apple.bluetooth.doap",
    "com.apple.coreaudio.allow-amr-encode",
    "com.apple.avfoundation.allow-capture-filter-rendering",
    "com.apple.private.avatar.store",
    "com.apple.CoreRoutine.SafetyMonitor",
    "com.apple.StatusKit.subscribe.types",
    "com.apple.messages.sticker-sharing-level",
    "com.apple.private.iosmac",
    "com.apple.private.coreservices.canaccessanysharedfilelist",
    "com.apple.private.opendirectoryd.modify_uuid",
    "com.apple.private.netfs.server.control",
    "com.apple.private.sysdiagnose.cli",
    "com.apple.developer.networking.multicast",
    "com.apple.private.launchservices.allowedtoget.LSPluginBundleIdentifierKey",
    "com.apple.activitymonitor-helper",
    "com.apple.private.launchservices.allowedtoget.LSActivePageUserVisibleOriginsKey",
    "com.apple.private.skywalk.observe-all",
    "com.apple.proactive.ProactiveSuggestionClientModel.xpc",
    "com.apple.private.nesessionmanager.privileged",
    "com.apple.private.security.system-async-io",
    "com.apple.private.biometrickit.allow-config",
    "com.apple.keystore.device.verify",
    "com.apple.private.biometrickit.allow-id-mgmt",
    "com.apple.security.device.firewire",
    "com.apple.private.systempreferences",
    "com.apple.private.assets.change-daemon-config",
    "com.apple.developer.extension-host.systemprefsapp.privacy",
    "com.apple.developer.extension-host.systemprefsapp.appleid",
    "com.apple.developer.extension-host.systemprefsapp.sharing",
    "com.apple.developer.security.privileged-file-operations",
    "com.apple.photondetector.iokit-user-access",
    "com.apple.driver.VADResource.user-access",
    "com.apple.pearl.iokit-user-access",
    "com.apple.private.cmio.extension.configuration",
    "com.apple.private.icfcallserver",
    "com.apple.private.rfbeventhelper.xpcaccepted",
    "com.apple.developer.copresence",
    "com.apple.private.screensharing.viewInvitation",
    "com.apple.private.netauth.get-credentials",
    "com.apple.IdentityLookup.message-filter",
    "com.apple.identitylookup.message-filter.extension-host",
    "com.apple.private.copresence.access-all-sessions",
    "com.apple.identitylookup.classification-ui.extension-host",
    "com.apple.telephonyutilities.callservicesdaemon.conversationmanager",
    "com.apple.identitylookup.classification.extension-host",
    "com.apple.private.security.iocatalog-management",
    "com.apple.private.security.only-bootkc-management",
    "com.apple.shortcuts.dialogpresentation",
    "com.apple.private.networkQuality",
    "com.apple.private.network.interface-control",
    "com.apple.private.network.intcoproc.restricted",
    "com.apple.private.notificationcenterui.nchostable",
    "com.apple.private.notificationcenter.snippet",
    "com.apple.locationd.prompt_from_background",
    "com.apple.locationd.prompt_behavior",
    "com.apple.private.accounts.allaccount",
    "com.apple.security.temporary-exception.sbpl:before:10.8",
    "com.apple.CoreTelephony.DataUsageInfo.allow",
    "com.apple.private.podcasts.PodcastContentService.client",
    "com.apple.coreaudio.app-tap",
    "com.apple.private.ClassKit.dashboard",
    "com.apple.springboard.activateassistant",
    "com.apple.mobile.keybagd.UserManager.logout",
    "com.apple.proactive.PersonalizationPortrait.NamedEntity.readOnly",
    "com.apple.private.coreservices.alwaysEligibleEvenWhenInBackground",
    "com.apple.container2",
    "com.apple.proactive.PersonalizationPortrait.Event",
    "com.apple.telephony.cupolicy-rw-access",
    "com.apple.private.intelligenceplatform.client-identifier",
    "com.apple.private.intelligenceplatform.use-cases",
    "com.apple.unencrypted.system-volume",
    "com.apple.private.security.bootpolicy.readonly",
    "com.apple.private.storage.revoke-access",
    "com.apple.apfs.unlock",
    "com.apple.private.nehelper.privileged",
    "com.apple.private.hid.client.alpha-numeric-remapping",
    "com.apple.private.dmc.set",
    "com.apple.developer.vfs.snapshot",
    "com.apple.private.applegraphicsdevicecontrol",
    "com.apple.authorization.smartcard.override",
    "com.apple.private.task_policy",
    "com.apple.avfoundation.allow-identifying-output-device-details",
    "com.apple.private.kernel.global-proc-info",
    "com.apple.wifi.temporary_log",
    "com.apple.private.security.nvram.wifi-psks",
    "com.apple.wifivelocity",
    "com.apple.private.bootcampassistant",
    "com.apple.private.security.storage.VoiceMemos",
    "com.apple.private.platformsso.agent",
    "com.apple.private.dark-wake-network-reachability",
    "com.apple.private.nsurlsession.allow-discretionary-cellular",
    "com.apple.developer.networking.multipath_extended",
    "com.apple.private.findmymac.locking",
    "com.apple.private.managedclient.configurationprofiles",
    "com.apple.private.opendirectoryd.securetoken",
    "com.apple.private.efilogin-helper",
    "com.apple.private.configurationprofiles.bootstraptoken.readonly",
    "com.apple.private.vfs.filesec-access",
    "com.apple.private.vfs.file-leases",
    "com.apple.private.trust-ubiquity-kvstore-identifier",
    "com.apple.private.security.storage.CoreRoutine",
    "com.apple.private.notificationcenter.server",
    "com.apple.private.push-to-wake",
    "com.apple.das.private.application.masquerade",
    "com.apple.apfs.wvek",
    "com.apple.mDNSResponder.log_utility",
    "com.apple.developer.on-demand-install-capable.BYPASS",
    "com.apple.developer.networking.multicast.BYPASS",
    "com.apple.private.libnotify.statecapture",
    "com.apple.private.endpoint-security.submit.openssh",
    "com.apple.private.vfs.authorized-access",
    "com.apple.fileprovider.acl-read",
    "com.apple.fileprovider.enumerate",
    "com.apple.fileprovider.acl-write",
    "com.apple.fileprovider.extension-host",
    "com.apple.private.vfs.skip-mtime-updates",
    "com.apple.internal.fileprovider.fpck",
    "com.apple.fileprovider.import-cookie",
    "com.apple.internal.fileprovider.debug",
    "com.apple.private.security.storage.auditd",
    "com.apple.private.protected-audit-control",
    "com.apple.private.endpoint-security.submit.su",
    "com.apple.security.get-task-allow entitlement",
    "com.apple.developer.networking.tcp_ka_offload",
    "com.apple.ibridge.control",
    "com.apple.private.iokit.system-nvram-internal-allow",
    "com.apple.private.icloud.findmydevice.account.modify",
    "com.apple.private.asr",
    "allow-obliterate-device",
    "com.apple.private.security.storage.spotlight",
    "com.apple.private.xprotect",
    "com.apple.private.iokit.rootdomain-set-property",
    "com.apple.private.iokit.soc-limit",
    "com.apple.private.iokit.powerlogging",
    "com.apple.private.iokit.batterydataprecise",
    "com.apple.private.SkyLight.displaycontrol",
    "com.apple.mobileactivationd.bridge",
    "com.apple.private.ndoagent",
    "com.apple.private.secure-apsclient",
    "com.apple.developer.extension-host.systeminfoapp",
    "com.apple.private.WebKit.UnrestrictedApplePay",
    "com.apple.security.sandbox",
    "com.apple.private.secure-apsclientv2",
    "modify-anchor-certificates",
    "com.apple.private.configurationprofiles.bootstraptoken.readwrite",
    "com.apple.managedconfiguration.teslad-access",
    "com.apple.security.temporary-exception.yasb",
    "com.apple.private.endpoint-security.submit.login",
    "com.apple.private.stackshot.stats",
    "com.apple.private.kernel.audio_latency",
    "com.apple.private.airplay.mangrove.client",
    "com.apple.private.virtio.sound.user-access",
    "com.apple.private.aop-audio.user-access",
    "com.apple.private.audio.coreaudiod",
    "com.apple.private.kernel.work-interval",
    "com.apple.private.driverkit.driver-access",
    "com.apple.private.xpc.launchd.job-manager",
    "com.apple.private.audio.driver-host",
    "com.apple.private.coreaudio.rpbserver",
    "com.apple.private.ZhuGeInternalSupport.CopyValue",
    "com.apple.private.aop-voicetrigger.user-access",
    "com.apple.signpostsupport.notification.listen",
    "com.apple.diagnosticpipeline.request",
    "com.apple.private.security.storage.spindump",
    "com.apple.lsapplicationproxy.deviceidentifierforvendor",
    "com.apple.private.security.sandbox-reference",
    "com.apple.private.distributed-notification-0v3",
    "com.apple.private.escrow-update",
    "com.apple.private.octagon.walrus",
    "com.apple.ScreenTimeAgent.private",
    "com.apple.symptom_analytics.refresh",
    "com.apple.symptom_analytics.setwatchpoint",
    "com.apple.wifi.ucm",
    "com.apple.logd.admin",
    "com.apple.private.kernel.ktrace-background",
    "com.apple.tailspin.symbolication",
    "com.apple.private.vfs.dataless-resolver",
    "com.apple.private.security.datavault.controller",
    "com.apple.geoservices.getmanifest",
    "com.apple.geoservices.utility",
    "com.apple.CoreRoutine.LocationOfInterest.Delete",
    "com.apple.CoreRoutine.Prediction",
    "com.apple.keystore.sik.acces",
    "com.apple.Maps.mapspushd.geod",
    "com.apple.navigation.spi",
    "com.apple.geoservices.experiments.set",
    "com.apple.CoreRoutine.VehicleLocation",
    "com.apple.geoanalyticsd.analytics",
    "com.apple.maps.debug-assistant",
    "com.apple.private.ids.messaging.high-priority",
    "com.apple.private.security.storage.MapsSync",
    "com.apple.geoservices.requestCounter",
    "com.apple.geoservices.shrinkdb",
    "com.apple.Maps.tripsharing.receiving",
    "com.apple.MapsSupport.MapsDaemon",
    "com.apple.maps.model-access",
    "com.apple.geoservices.changetilegroup",
    "com.apple.geoservices.experiments.fetchall",
    "com.apple.coreduetd.knowledge",
    "com.apple.CoreRoutine.MapHint",
    "com.apple.wifi.set_power",
    "com.apple.icloud.searchpartyuseragent.beaconmanager",
    "com.apple.icloud.searchpartyuseragent.ownersession",
    "com.apple.diskimages.attach",
    "com.apple.private.storagekitd.mountaudit",
    "com.apple.private.sportskit.client",
    "com.apple.watchlist.private.playback-report",
    "com.apple.private.debug_port",
    "com.apple.private.logging.stream.darwinos",
    "com.apple.appstored.manage-iap",
    "com.apple.developer.openURL",
    "com.apple.ap.adservicesd.statusconditionclient.allow_write",
    "com.apple.private.appstorecomponents.media-client-version",
    "com.apple.familycircle.agent",
    "com.apple.aned.private.ANEAccess.allow",
    "com.apple.private.ad.analytics",
    "com.apple.private.safari.can-use-launch-agent",
    "com.apple.private.iad.open-privacy-view-controller",
    "com.apple.private.ids.remoteurlconnection",
    "com.apple.private.iad.unlimited-controllers-allowed",
    "com.apple.security.temporary-exception.process-info",
    "com.apple.springboard.xzfwk.customimage",
    "com.apple.backboardd.hostCanRequireTouchesFromHostedContent",
    "com.apple.private.appstorecomponents.media-client-id",
    "com.apple.proactive.PersonalizationPortrait.Config",
    "com.apple.private.dt.automationmode.privileged-writer-client",
    "com.apple.SocialLayer",
    "com.apple.security.library-repair.ostype",
    "com.apple.private.photos.allowlibraryupgrade",
    "com.apple.private.photolibrarymigrationutility.write-access",
    "com.apple.private.translation",
    "com.apple.private.photos.service.diagnostics",
    "com.apple.private.photos.service.librarymanagement",
    "com.apple.private.photos.allowassetexpunge",
    "com.apple.private.photolibraryd.write-access",
    "com.apple.private.photos.allowdirectdbwrite",
    "com.apple.security.library-repair.extensions",
    "com.apple.private.Photos.CPLDiagnose",
    "com.apple.private.coreservices.definesExtensionPoint",
    "com.apple.runningboard.assertions.shortcuts",
    "com.apple.private.mediaexperience.startrecordinginthebackground.allow",
    "com.apple.springboard.lockDevice",
    "com.apple.private.sessionkit.sessionRequest",
    "com.apple.private.activitykit.ephemeralActivityRequester",
    "com.apple.private.sessionkit.custom-platter-target",
    "com.apple.private.xpc.launchd.loginitem-bootstrapper",
    "Outgoing Network Connections",
    "com.apple.private.xpc.launchd.loginitem-outside-bundle",
    "com.apple.private.xpc.launchd.app-state-manager",
    "com.apple.private.xpc.launchd.enable-disable-system-services",
    "com.apple.private.xpc.launchd.obliterator",
    "com.apple.private.xpc.launchd.service-hold",
    "com.apple.private.xpc.launchd.reboot",
    "com.apple.private.xpc.launchd.per-user-lookup",
    "com.apple.private.xpc.launchd.per-user-create.mbsetupuser",
    "com.apple.private.xpc.domain-extension.proxy",
    "com.apple.private.xpc.persona-manager",
    "com.apple.developer.push-to-talk",
    "com.apple.developer.coremedia.hls.interstitial-preview",
    "com.apple.developer.media-device-discovery-extension",
    "com.apple.developer.payment-pass-provisioning",
    "com.apple.private.usage-tracking",
    "com.apple.private.security.storage.NanoTimeKit.FaceSupport",
    "com.apple.rootless.storage.timezone",
    "com.apple.private.security.storage.Lockdown",
    "com.apple.rootless.storage.facekit",
    "com.apple.private.security.storage.IdentityServices",
    "com.apple.rootless.storage.proactivepredictions",
    "com.apple.private.security.storage.Biome",
    "com.apple.rootless.storage.com.apple.MobileAsset.HomeKit",
    "com.apple.rootless.storage.com.apple.MobileAsset.EmbeddedNL",
    "com.apple.private.security.storage.iCloudDrive",
    "com.apple.rootless.storage.com.apple.MobileAsset.network.networknomicon",
    "com.apple.private.security.storage.CloudKit",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceTriggerAssets",
    "com.apple.private.security.storage.CoreKnowledge",
    "com.apple.rootless.storage.sensorkit",
    "com.apple.rootless.storage.CoreRoutine",
    "com.apple.private.security.storage.SecureElementService",
    "com.apple.private.security.storage.demo_backup",
    "com.apple.rootless.storage.com.apple.MobileAsset.DeviceCheck",
    "com.apple.private.security.storage.automation-mode",
    "com.apple.rootless.storage.com.apple.MobileAsset.CarPlayAppBlacklist",
    "com.apple.private.security.storage.trustd-private",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceServicesVocalizerVoice",
    "com.apple.private.security.storage.fpsd",
    "com.apple.private.security.storage.SearchParty",
    "com.apple.private.security.storage.SoC",
    "com.apple.private.security.storage.containers",
    "com.apple.private.security.storage.adprivacyd",
    "com.apple.private.security.storage.Wireless",
    "com.apple.private.security.storage.idcredd",
    "com.apple.private.security.storage.multimodalsearchd",
    "com.apple.rootless.storage.coreknowledge",
    "com.apple.rootless.storage.siriremembers",
    "com.apple.rootless.storage.com.apple.MobileAsset.SiriShortcutsMobileAsset",
    "com.apple.rootless.storage.MusicApp",
    "com.apple.private.security.storage.SymptomFramework",
    "com.apple.private.security.storage.Health",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceServices.GryphonVoice",
    "com.apple.private.security.storage.amfid",
    "com.apple.rootless.storage.fpsd",
    "com.apple.private.security.storage.Cryptex",
    "com.apple.rootless.storage.com.apple.MobileAsset.HealthKt.FeatureAvailability",
    "com.apple.rootless.storage.com.apple.MobileAsset.Font5",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceServices.CustomVoice",
    "com.apple.rootless.storage.CoreAnalytics",
    "com.apple.private.security.storage.CarrierBundles",
    "com.apple.private.security.storage.PrivacyAccounting",
    "com.apple.rootless.storage.nsurlsessiond",
    "com.apple.private.security.storage.kbd",
    "com.apple.private.security.storage.triald",
    "com.apple.rootless.storage.ExtensibleSSO",
    "com.apple.private.security.storage.SpeechPersonalizedLM",
    "com.apple.rootless.storage.coreidvd",
    "com.apple.rootless.storage.QLThumbnailCache",
    "com.apple.rootless.storage.RoleAccountStaging",
    "com.apple.rootless.storage.com.apple.MobileAsset.SharingDeviceAssets",
    "com.apple.private.security.storage.SiriReferenceResolution",
    "com.apple.private.security.storage.Spotlight",
    "com.apple.rootless.storage.com.apple.MobileAsset.DictionaryServices.dictionary2",
    "com.apple.rootless.storage.com.apple.MobileAsset.PKITrustSupplementals",
    "com.apple.private.security.storage.MobileContainerManager",
    "com.apple.rootless.storage.com.apple.MobileAsset.MXLongFormVideoApps",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceServices.VoiceResources",
    "com.apple.private.security.storage.trustd",
    "com.apple.rootless.storage.apfs_boot_mount",
    "com.apple.private.security.storage.Suggestions",
    "com.apple.private.security.storage.HomeAI",
    "com.apple.private.security.storage.DocumentRevisions",
    "com.apple.private.security.storage.familycircled",
    "com.apple.rootless.storage.dmd",
    "com.apple.rootless.storage.pearl-field-diagnostics",
    "com.apple.rootless.storage.com.apple.MobileAsset.DuetExpertCenterAsset",
    "com.apple.private.security.storage.sysdagnose.ScreenshotServicesService",
    "com.apple.private.security.storage.FaceTime",
    "com.apple.rootless.storage.CoreSpeech",
    "com.apple.private.security.storage.MobileIdentityService",
    "com.apple.rootless.storage.com.apple.mediaanalysisd",
    "com.apple.private.security.storage.DumpPanic",
    "com.apple.rootless.storage.com.apple.MobileAsset.MailDynamicData",
    "com.apple.private.security.storage.SensorKit",
    "com.apple.private.security.storage.TCC",
    "com.apple.rootless.storage.dprivacyd_storage",
    "com.apple.private.security.storage.mobilesync",
    "com.apple.private.security.storage.SiriVocabulary",
    "com.apple.rootless.storage.voiceshortcuts",
    "com.apple.private.security.storage.Keychains",
    "com.apple.private.security.storage.pipelined",
    "com.apple.private.security.storage.Voicemail",
    "com.apple.rootless.storage.clientScripter",
    "com.apple.rootless.storage.com.apple.MobileAsset.MacinTalkVoiceAssets",
    "com.apple.private.security.storage.chronod",
    "com.apple.private.security.storage.CoreFollowUp",
    "com.apple.private.security.storage.Calendar",
    "com.apple.private.security.storage.SiriInference",
    "com.apple.private.security.storage.TimeMachine",
    "com.apple.private.security.storage.StatusKit",
    "com.apple.rootless.storage.com.apple.MobileAsset.TimeZoneUpdate",
    "com.apple.rootless.storage.com.apple.MobileAsset.VoiceServices.CombinedVocalizerVoices",
    "com.apple.rootless.storage.com.apple.MobileAsset.Font6",
    "com.apple.developer.kernel.extended-virtual-addressing",
]


class CodeDirectoryException(Exception):
    pass


class EntitlementException(Exception):
    pass


class EntitlementsExtractor:

    kSecCodeSignatureLibraryValidation = 0x2000 # require library validation
    kSecCodeSignatureRestrict = 0x0800 # restrict dyld loading
    kSecCodeSignatureRuntime = 0x10000

    """
    Scan file system extracting entitlements from Mach-O binaries (and the raw code signature segment).
    """

    def __init__(self, verbose=False, use_all_entitlements=True):
        self.verbose = verbose
        self.entitlements_db = dict()
        self.use_all_entitlements = use_all_entitlements

    def _find_code_directory_magic(self, plist):
        """
        finds 0xfade0c02 (code directory magic) in memoryview object - returns None if not found
        CSMAGIC_CODEDIRECTORY 0xfade0c02 - bsd/sys/codesign.h
        """
        for i in range(len(plist)):
            if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x0C and plist[i+3] == 0x02:
                return i
        return None

    def _find_embedded_entitlements_magic(self, plist):
        """
        finds 0xFADE7171 (entitlement magic) in memoryview object - returns None if not found
        CSMAGIC_EMBEDDED_ENTITLEMENTS 0xFADE7171 - bsd/sys/codesign.h
        """
        for i in range(len(plist)):
            if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x71 and plist[i+3] == 0x71:
                return i
        return None

    def _find_embedded_der_entitlements_magic(self, plist):
        """
        finds 0xFADE7172 (der entitlement magic) in memoryview object - returns None if not found
        CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xFADE7172 - bsd/sys/codesign.h
        """
        for i in range(len(plist)):
            if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x71 and plist[i+3] == 0x72:
                return i
        return None

    def _get_int(self, plist, offset):
        """
        returns next 4 bytes as int
        """
        return int.from_bytes(plist[offset:offset+4], byteorder='big')

    def _verify_xml(self, plist, offset):
        """
        verify that start of buffer is <?xml
        """
        return plist[offset:offset+6] == b'<?xml ' # or plist[offset:offset+5] == b'<!-- '

    def _find_xml(self, plist):
        """
        Finds XML string in memoryview object - returns None if not found
        """
        for i in range(len(plist)):
            if self._verify_xml(plist, i):
                return i
        return None

    def _bytes_to_plist(self, plistbytes):
        """
        Converts bytes to plist object
        """
        try:
            plist = plistlib.loads(plistbytes, fmt=plistlib.FMT_XML)
        except Exception as e:
            if self.verbose:
                print('Error parsing plist: {}'.format(e))
            plist = None
        return plist

    def _is_hardened(self, flags):
        """ Returns True if binary is hardened """
        return False if flags is None else (flags & EntitlementsExtractor.kSecCodeSignatureRuntime) == EntitlementsExtractor.kSecCodeSignatureRuntime

    def _parse_binary(self, executable_path):

        def _signal_handler(signum, frame):
            raise TimeoutError()

        # Timeout setup
        signal.signal(signal.SIGALRM, _signal_handler)
        signal.alarm(TIMEOUT_DEFAULT)
        try:
            fat_binary = lief.MachO.parse(executable_path)
        except TimeoutError:
            if self.verbose:
                print(f'[WARN] Timeout parsing binary: {executable_path}')
            return None
        finally:
            signal.alarm(0)

        return fat_binary

    def _extract_code_directory_flags(self, binary):
        """
        Extracts CodeDirectory flags from the binary
        Arguments:
            binary: lief binary object
        returns flags as an int
        raises CodeDirectoryException on error
        """
        signature = binary.code_signature

        code_directory_offset = self._find_code_directory_magic(signature.content)
        if code_directory_offset is None:
            raise CodeDirectoryException('No code directory magic found')
        # if self.verbose:
        #     print('CodeDirectory offset: {}'.format(code_directory_offset))

        # sanity check
        code_directory_buffer_length = self._get_int(signature.content, code_directory_offset+4)
        if code_directory_offset + code_directory_buffer_length > len(signature.content):
            raise CodeDirectoryException('CodeDirectory declared length exceeds overall segment length')

        # MAGIC[4] - LENGTH[4] - VERSION[4] - FLAGS[4] ...other stuff...
        if code_directory_buffer_length < 16:
            raise CodeDirectoryException('CodeDirectory declared length is too short')

        return self._get_int(signature.content, code_directory_offset+12)

    def _extract_entitlement_bytes(self, binary):
        """ 
        Extracts entitlements plist from executable as bytes
        Arguments:
            binary: lief binary object
        
        returns both the (full_bytes, xml_bytes)
            returns "full_bytes" cause plistlib struggles when <?xml is not the start of what it receives
        
        raises EntitlementException if not found
        """
        def _signal_handler(signum, frame):
            raise TimeoutError()

        # Timeout setup
        signal.signal(signal.SIGALRM, _signal_handler)
        signal.alarm(TIMEOUT_DEFAULT)
        try:
            signature = binary.code_signature

            entitlements_offset = self._find_embedded_entitlements_magic(signature.content)
            if entitlements_offset is None:
                entitlements_offset = self._find_embedded_der_entitlements_magic(signature.content)
                if entitlements_offset is not None:
                    raise EntitlementException('DER entitlements not supported')
                raise EntitlementException('No entitlements magic found')

            # if self.verbose:
            #     print('Entitlements offset: {}'.format(entitlements_offset))

            entitlements_buffer_length = self._get_int(signature.content, entitlements_offset+4)
            # if self.verbose:
            #     print('Entitlements buffer length: {}'.format(entitlements_buffer_length))

            if entitlements_offset + entitlements_buffer_length > len(signature.content):
                raise EntitlementException('Entitlements declared length exceeds overall segment length')

            full_buffer = signature.content[entitlements_offset+8:entitlements_offset+entitlements_buffer_length]
            # if self.verbose:
            #     print('Entitlements: {}'.format(full_buffer.tobytes()))

            xml_start_tag_offset = self._find_xml(full_buffer)
            if xml_start_tag_offset is None:
                raise EntitlementException('Entitlements are not XML')
            xml_plist = full_buffer[xml_start_tag_offset:]

            xml_plist = xml_plist.tobytes().rstrip(b'\x00')
            # if self.verbose:
            #     print('Entitlements (post strip): {}'.format(xml_plist))
        except TimeoutError:
            if self.verbose:
                print(f'[WARN] Timeout extracting entitlements')
            return None, None
        finally:
            signal.alarm(0)

        # full_buffer returned cause plistlib struggles when <?xml is not the start of what it receives
        return xml_plist, full_buffer.tobytes()

    def _find_entitlements(self, plistbytes):
        """ Prints entitlements plist to stdout """
        plist = self._bytes_to_plist(plistbytes)
        if plist is None:
            return dict()
        return plist

    def get_entitlements_sample(self, binary_path):
        """ 
        Extracts entitlements from a single binary
        """

        fat_binary = self._parse_binary(binary_path)
        if fat_binary is None:
            return []
        binaries = [fat_binary.at(idx) for idx in range(fat_binary.size)]

        if self.verbose:
            print('\nAnalyzing {}:'.format(binary_path))

        entitlements = set()
        entitlements_full = dict()
        for binary in binaries:
            if (not binary.has_code_signature) or binary.code_signature is None:
                if self.verbose:
                    print('[WARN] No code signature segment found')
                return []

            code_signature = binary.code_signature.content

            # try:
            #     cd_flags = self._extract_code_directory_flags(binary)
            # except CodeDirectoryException as e:
            #     cd_flags = None
            # if self.verbose:
            #     print('Flags: 0x{:08X} Hardened: {}'.format(cd_flags, self._is_hardened(cd_flags)))

            try:
                xml_plist, entitlement_buffer = self._extract_entitlement_bytes(binary)
            except EntitlementException as e:
                if self.verbose:
                    print(f'[WARN] Error extracting entitlements: from {binary_path}: {e}')
                return []
            except Exception as error:
                if self.verbose:
                    print(f'[WARN] Unexpected error extracting entitlements: from {binary_path}: {error}')
                return []

            entitlements_binary = self._find_entitlements(xml_plist)
            entitlements.update(list(entitlements_binary.keys()))
            entitlements_full.update(entitlements_binary)

        if self.verbose:
            if len(entitlements_full) == 0:
                print('[INFO] No entitlements found')
            for key, value in entitlements_full.items():
                print(f'{key}: {value}')

        return list(entitlements)

    def _normalize_entitlements(self, entitlements):
        normalized_entitlements = list()
        for entitlement in entitlements:
            if entitlement == 'application-identifier':
                normalized_entitlements.append('com.apple.application-identifier')
            elif entitlement == 'aps-environment':
                normalized_entitlements.append('com.apple.developer.aps-environment')
            elif entitlement == 'get-task-allow':
                normalized_entitlements.append('com.apple.security.get-task-allow')
            elif entitlement == 'aps-connection-initiate':
                normalized_entitlements.append('com.apple.private.aps-connection-initiate')
            else:
                normalized_entitlements.append(entitlement)
        
        return set(normalized_entitlements)

    def extract_features(self, binary_path):
        entitlemements_features = ENTITLEMENTS_FEATURES_ALL if self.use_all_entitlements else ENTITLEMENTS_FEATURES_FINAL
        entitlemements_sample = self.get_entitlements_sample(binary_path)
        entitlemements_sample = self._normalize_entitlements(entitlemements_sample)
        features = [1 if entitlement in entitlemements_sample else 0 for entitlement in entitlemements_features]
        return features

    def get_entitlements(self, dataset_path):

        with open(dataset_path, 'r') as f:
            dataset = _pandas().read_csv(f)

        for index, row in dataset.iterrows():
            binary_path = row['path']
            label = row['label']
            archs = eval(row['arch'])
            if 'i386' in archs:
                continue
            entitlements_binary = self.get_entitlements_sample(binary_path)

            sample_label = "goodware" if label == 0 else "malware"
            for entitlement in entitlements_binary:
                if entitlement in self.entitlements_db:
                    if sample_label in self.entitlements_db[entitlement]:
                        self.entitlements_db[entitlement][sample_label] += 1
                    else:
                        self.entitlements_db[entitlement][sample_label] = 1
                else:
                    self.entitlements_db[entitlement] = {sample_label: 1}
        
            with open('entitlements_db.json', 'w') as f:
                json.dump(self.entitlements_db, f)


if __name__ == "__main__":
    extractor = EntitlementsExtractor(verbose=True)
    extractor.get_entitlements(DATASET_PATH)