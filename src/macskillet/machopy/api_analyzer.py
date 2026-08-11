import ast
import lief
import json
import signal
import re
import os
import warnings

# pandas is only needed by the dataset-iteration helpers below, which are
# research utilities rather than part of the analysis path. Importing it at
# module scope made `portable`-only installs fail to read entitlements and
# certificates at all -- silently, since callers catch ImportError.
def _pandas():
    import pandas as pd

    return pd



lief.logging.disable()
DATASET_PATH = 'dataset_info.csv'
TIMEOUT_DEFAULT = 240
API_DB_PATH = 'api_db_final.json'

TOP_APIS = 400
MIN_APPS_FILTER = 10

#: API-frequency database derived from the training corpus. Not redistributed
#: (it is a dataset artifact), so absence is normal and must not break import.
#: Point MACSKILLET_API_INFO at your own copy to enable the API feature block.
API_INFO_PATH = os.environ.get(
    'MACSKILLET_API_INFO',
    os.path.join(os.path.dirname(__file__), 'data',
                 f'macos_api_N{MIN_APPS_FILTER}_K{TOP_APIS}.json'),
)

API_CATEGORIES = [
    "AppKit_Foundation",
    "AudioToolbox",
    "AVFoundation",
    "BackgroundTasks",
    "BrowserEngineKit",
    "CallKit",
    "CFNetwork",
    "CloudKit",
    "Contacts",
    "CoreAudio",
    "CoreBluetooth",
    "CoreFoundation",
    "CoreGraphics",
    "CoreImage",
    "CoreLocation",
    "CoreMedia",
    "CoreMediaIO",
    "CoreServices",
    "CoreTelephony",
    "CoreWLAN",
    "DiskArbitration",
    "EndpointSecurity",
    "EventKit",
    # "Foundation",
    "Kernel",
    "Messages",
    "Metal",
    "Network",
    "NotificationCenter",
    "OSLog",
    "Security",
    "Speech",
    "SystemConfiguration",
    "UserNotifications",
    "WebKit"
]


def get_api_names():
    """Flat list of API names from the frequency DB.

    Returns an empty list when the DB is absent. This is called at import time
    by static_feat_extractor, so raising here would make the whole ML module
    unimportable in a fresh clone — the DB is a dataset artifact, not code.
    """
    if not os.path.isfile(API_INFO_PATH):
        warnings.warn(
            f"API info DB not found at {API_INFO_PATH}; API features disabled. "
            "Set MACSKILLET_API_INFO to enable them.",
            RuntimeWarning,
            stacklevel=2,
        )
        return []
    with open(API_INFO_PATH, 'r') as f:
        api_info = json.load(f)
    return [api for apis in api_info.values() for api in apis.keys()]


class APIExtractor:
    """
    Extract API (Objective-C and Swift classes) from Mach-O binaries.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.entitlements_db = dict()

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
                print(f'[WARN] Timeout parsing binary')
            return None
        finally:
            signal.alarm(0)

        return fat_binary

    def _parse_symbol(self, symbol):
        if not isinstance(symbol, str):
            return ''
        if symbol.startswith('_OBJC_CLASS_$_'):
            return symbol.replace('_OBJC_CLASS_$_', '')
        elif symbol.startswith('_OBJC_METACLASS_$_'):
            return symbol.replace('_OBJC_METACLASS_$_', '')
        elif symbol.startswith('___'):
            return symbol[3:]
        elif symbol.startswith('__'):
            return symbol[2:]
        elif symbol.startswith('_'):
            return symbol[1:]
        
        if symbol.endswith('0__'):
            return symbol[:-3]

        return symbol

    def get_api_sample(self, binary_path):
        """ 
        Extracts API from a single binary
        """

        fat_binary = self._parse_binary(binary_path)
        if fat_binary is None:
            return []
        binaries = [fat_binary.at(idx) for idx in range(fat_binary.size)]

        if self.verbose:
            print('\nAnalyzing {}:'.format(binary_path))

        api = set()
        for binary in binaries:
            # for group in [binary.functions, binary.exported_functions, binary.imported_functions]:
            for group in [binary.imported_functions]:
                for func in group:
                    try:
                        func_name = func.name.decode('utf-8') if isinstance(func.name, bytes) else func.name
                    except Exception:
                        continue
                    func_name = self._parse_symbol(func_name)
                    if func_name == "" or "$" in func_name or func_name.startswith("_") or func_name.endswith("_") or func_name.endswith("_struct") or \
                            func_name.startswith("k") or func_name.startswith("Z") or func_name.startswith("T0") or \
                            func_name.startswith("symbolic ") or func_name.startswith("OBJC_IVAR_") or \
                            func_name.startswith("associated ") or func_name.startswith("OBJC_PROTOCOL_") :
                        continue
                    api.add(func_name)

        return api

    def extract_features(self, binary_path):
        assert os.path.isfile(API_INFO_PATH), f"File not found: {API_INFO_PATH}"
        api_sample = self.get_api_sample(binary_path)

        with open(API_INFO_PATH, 'r') as f:
            api_info = json.load(f)
        api_names = [api for apis in api_info.values() for api in apis.keys()]
        assert len(set(api_names)) == len(api_names), "API names are not unique"

        features = [1 if api in api_sample else 0 for api in api_names]

        return features

    def extract_api(self, dataset_path):
        api_db = dict()

        with open(dataset_path, 'r') as f:
            dataset = _pandas().read_csv(f)

        for index, row in dataset.iterrows():
            binary_path = row['path']
            label = row['label']
            archs = ast.literal_eval(row['arch'])
            if 'i386' in archs:
                continue
            api_sample = self.get_api_sample(binary_path)

            sample_label = "goodware" if label == 0 else "malware"
            for api in api_sample:
                if api in api_db:
                    if sample_label in api_db[api]:
                        api_db[api][sample_label] += 1
                    else:
                        api_db[api][sample_label] = 1
                else:
                    api_db[api] = {sample_label: 1}
        
            with open(API_DB_PATH, 'w') as f:
                json.dump(api_db, f)

    def analyze_api(self):
        if not os.path.isfile(API_DB_PATH):
            self.extract_api(DATASET_PATH)

        with open(API_DB_PATH, 'r') as f:
            data = json.load(f)

        api_categories = {category: {} for category in API_CATEGORIES}
        parsed_data = {}

        for api, apps_count in data.items():
            if sum(apps_count.values()) < MIN_APPS_FILTER:
                continue

            if 'goodware' not in apps_count:
                apps_count['goodware'] = 0
            if 'malware' not in apps_count:
                apps_count['malware'] = 0
            parsed_data[api] = apps_count

            if re.match("^NS[A-Z]", api):
                # NOTE: We collect together AppKit and Foundation APIs because both frameworks have APIs with the same prefix (NS).
                api_categories["AppKit_Foundation"][api] = apps_count
            elif re.match("^Audio[A-Z]", api):
                api_categories["AudioToolbox"][api] = apps_count
            elif re.match("^AV[A-Z]", api):
                api_categories["AVFoundation"][api] = apps_count
            elif re.match("^BG[A-Z]", api):
                api_categories["BackgroundTasks"][api] = apps_count
            elif re.match("^BE[A-Z]", api):
                api_categories["BrowserEngineKit"][api] = apps_count
            elif re.match("^CX[A-Z]", api):
                api_categories["CallKit"][api] = apps_count
            elif re.match("^CF[A-Z]", api):
                api_categories["CFNetwork"][api] = apps_count
            elif re.match("^CK[A-Z]", api):
                api_categories["CloudKit"][api] = apps_count
            elif re.match("^CN[A-Z]", api):
                api_categories["Contacts"][api] = apps_count
            elif re.match("^Audio[A-Z]", api):
                api_categories["CoreAudio"][api] = apps_count
            elif re.match("^CB[A-Z]", api):
                api_categories["CoreBluetooth"][api] = apps_count
            elif re.match("^CF[A-Z]", api):
                api_categories["CoreFoundation"][api] = apps_count
            elif re.match("^CG[A-Z]", api):
                api_categories["CoreGraphics"][api] = apps_count
            elif re.match("^CI[A-Z]", api):
                api_categories["CoreImage"][api] = apps_count
            elif re.match("^CL[A-Z]", api):
                api_categories["CoreLocation"][api] = apps_count
            elif re.match("^CM[A-Z]", api):
                api_categories["CoreMedia"][api] = apps_count
            elif re.match("^CMIO[A-Z]", api):
                api_categories["CoreMediaIO"][api] = apps_count
            elif re.match("^CS[A-Z]", api):
                api_categories["CoreServices"][api] = apps_count
            elif re.match("^CT[A-Z]", api):
                api_categories["CoreTelephony"][api] = apps_count
            elif re.match("^CW[A-Z]", api):
                api_categories["CoreWLAN"][api] = apps_count
            elif re.match("^DA[A-Z]", api):
                api_categories["DiskArbitration"][api] = apps_count
            elif re.match("^es", api):
                api_categories["EndpointSecurity"][api] = apps_count
            elif re.match("^EK[A-Z]", api):
                api_categories["EventKit"][api] = apps_count
            # elif re.match("^IOBluetooth[A-Z]", api):
            #     api_categories["IOBluetooth"][api] = apps_count
            elif (re.match("^IO[A-Z]", api) or
                    # kern
                    re.match("^OS[A-Z]", api) or re.match("^hv_", api) or re.match("^kcs_", api) or re.match("^kpc_", api) or re.match("^lck_", api) or re.match("^task_", api) or re.match("^clock_", api) or
                    # miscfs
                    re.match("^fifo_", api) or
                    # net
                    re.match("^inet_", api) or re.match("^bpf_", api) or re.match("^ether_", api) or
                    # sys
                    re.match("^buf_", api) or re.match("^ctl_", api) or re.match("^file_", api) or re.match("^proc_", api) or re.match("^sysctl_", api) or re.match("^vnop_", api) or re.match("^vnode_", api) or
                    # vm
                    re.match("^vm_", api) or
                    # mach
                    re.match("^mach_", api) or
                    # mach-o
                    re.match("^dylib_", api) or
                    # debugging
                    re.match("^kdbg_", api) or
                    # others
                    re.match("^Secure[A-Z]", api) or re.match("^kauth_", api)):
                api_categories["Kernel"][api] = apps_count
            elif re.match("^MS[A-Z]", api):
                api_categories["Messages"][api] = apps_count
            elif re.match("^MT[A-Z]", api):
                api_categories["Metal"][api] = apps_count
            elif re.match("^NW[A-Z]", api) or re.match("^NE[A-Z]", api):
                api_categories["Network"][api] = apps_count
            # elif re.match("^NE[A-Z]", api):
            #     api_categories["NetworkExtension"][api] = apps_count
            elif re.match("^NC[A-Z]", api):
                api_categories["NotificationCenter"][api] = apps_count
            elif re.match("^OSLog[A-Z]", api):
                api_categories["OSLog"][api] = apps_count
            elif re.match("^Sec[A-Z]", api) or re.match("^CMS[A-Z]", api) or re.match("SF[A-Z]", api) or re.match("^Session", api):  # re.search("sec", api, re.IGNORECASE)
                api_categories["Security"][api] = apps_count
            elif re.match("^SFSpeech[A-Z]", api):
                api_categories["Speech"][api] = apps_count
            elif re.match("^SC[A-Z]", api):
                api_categories["SystemConfiguration"][api] = apps_count
            elif re.match("^UN[A-Z]", api):
                api_categories["UserNotifications"][api] = apps_count
            elif re.match("^WK[A-Z]", api):
                api_categories["WebKit"][api] = apps_count

        # sort data by the sum of the number of apps (both goodware and malware) that have each entitlement
        sorted_data = sorted(parsed_data.items(), key=lambda x: sum(x[1].values()), reverse=True)

        print(f"\nTotal number of api: {len(sorted_data)}")

        # sorted_data = sorted_data[:TOP_APIS]
        # find all system APIs (syscalls, C functions, etc.) included in sorted_data but not yet in api_categories and add them to the "Kernel" category
        found_apis = set([api for api_list in api_categories.values() for api in api_list])
        for api, apps_count in sorted_data[:TOP_APIS]:
            if api not in found_apis:
                if not api.startswith("objc") and re.match("^[a-z]", api):
                    api_categories["Kernel"][api] = apps_count

        # sort the APIs in each category by the number of apps that have them
        for category, apis in api_categories.items():
            api_categories[category] = dict(sorted(apis.items(), key=lambda x: sum(x[1].values()), reverse=True))

        # print the number and list of APIs in each category
        for category, apis in api_categories.items():
            print(f"> {category} ({len(apis)}):")
            for api, apps_count in apis.items():
                print(f"  * {api}: {apps_count}")

        print(f"Total number of APIs: {len([api for api_list in api_categories.values() for api in api_list])}")

        save_path = f"macos_api_N{MIN_APPS_FILTER}_K{TOP_APIS}.json"
        if not os.path.isfile(save_path):
            with open(save_path, "w") as f:
                json.dump(api_categories, f, indent=4)


if __name__ == "__main__":
    extractor = APIExtractor(verbose=True)
    extractor.analyze_api()
