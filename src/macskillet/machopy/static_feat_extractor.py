import os
import numpy as np
from sklearn.feature_extraction import FeatureHasher
import itertools
import re
import lief
lief.logging.disable()
import hashlib
import multiprocessing
import pandas as pd
import string
from macskillet.machopy.entitlements_extractor import EntitlementsExtractor, ENTITLEMENTS_FEATURES_FINAL, ENTITLEMENTS_FEATURES_ALL
from macskillet.machopy.code_signature_verifier import verify_code_signature
import signal
import collections
import base64
from macskillet.machopy.api_analyzer import APIExtractor, get_api_names
from macskillet.common.strings import count_categories, is_base64, iter_strings

import warnings
warnings.filterwarnings('ignore')


FEATURE_TYPES = ['structural', 'byte', 'string', 'entitlements', 'entitlements_all', 'packing', 'persistence', 'api', 'certificates']
TIMEOUT_DEFAULT = 600  # 10 minutes
# Common names for the segments when using packers: UPX = {'__XHDR', 'UPX_DATA', 'upxTEXT'}, Mpress = {'__MPRESS__'}
# We search for these patterns using regex (e.g., re.search(r'XHDR|UPX_DATA|upxTEXT|MPRESS', segment.name, re.IGNORECASE))
SEGMENT_NAMES_PACKING_PATTERNS = r"XHDR|UPX_DATA|upxTEXT|MPRESS"
ENTROPY_THRESHOLD = 7.0
PACKING_RATIO_THRESHOLD = 0.2 # 20%, based on The Art of Mac Malware vol.2 (https://taomm.org/vol2/detection.html) and Pefile (https://github.com/erocarrera/pefile/blob/4b3b1e2e568a88d4f1897d694d684f23d9e270c4/peutils.py#L555)
#: Ships with the package; override with MACSKILLET_API_INFO for a custom DB.
API_INFO_PATH = os.environ.get(
    'MACSKILLET_API_INFO',
    os.path.join(os.path.dirname(__file__), 'data', 'macos_api_N10_K400.json'),
)


STRUCTURAL_FEATURES = [
    "size", "virtual_size",
    "flag_allmodsbound", "flag_allow_stack_execution", "flag_app_extension_safe", "flag_bindatload", "flag_binds_to_weak",
    "flag_canonical", "flag_dead_strippable_dylib", "flag_dyldlink", "flag_force_flat", "flag_has_tlv_descriptors",
    "flag_incrlink", "flag_lazy_init", "flag_nofixprebinding", "flag_nomultidefs", "flag_noundefs", "flag_no_heap_execution",
    "flag_no_reexported_dylibs", "flag_pie", "flag_prebindable", "flag_prebound", "flag_root_safe", "flag_setuid_safe",
    "flag_split_segs", "flag_subsections_via_symbols", "flag_twolevel", "flag_weak_defines",
    "lc_build_version", "lc_code_signature", "lc_data_in_code", "lc_dyld_chained_fixups",
    "lc_dyld_environment", "lc_dyld_exports_trie", "lc_dyld_info", "lc_dyld_info_only", "lc_dylib_code_sign_drs", "lc_dysymtab",
    "lc_encryption_info", "lc_encryption_info_64", "lc_fileset_entry", "lc_function_starts", "lc_fvmfile", "lc_ident", "lc_idfvmlib",
    "lc_id_dylib", "lc_id_dylinker", "lc_lazy_load_dylib", "lc_linker_optimization_hint", "lc_linker_option", "lc_loadfvmfile",
    "lc_load_dylib", "lc_load_dylinker", "lc_load_upward_dylib", "lc_load_weak_dylib", "lc_main", "lc_note", "lc_prebind_cksum",
    "lc_prebound_dylib", "lc_prepage", "lc_reexport_dylib", "lc_routines", "lc_routines_64", "lc_rpath", "lc_segment", "lc_segment_64",
    "lc_segment_split_info", "lc_source_version", "lc_sub_client", "lc_sub_framework", "lc_sub_library", "lc_sub_umbrella", "lc_symseg",
    "lc_symtab", "lc_thread", "lc_twolevel_hints", "lc_unixthread", "lc_uuid",
    "section_size_min", "section_size_max", "section_size_avg", "section_entropy_min", "section_entropy_max", "section_entropy_avg",
    "lc_size_min", "lc_size_max", "lc_size_avg", "lc_entropy_min", "lc_entropy_max", "lc_entropy_avg",
    "segments_size_min", "segments_size_max", "segments_size_avg", "segments_entropy_min", "segments_entropy_max", "segments_entropy_avg",
    "segments_virtual_size_min", "segments_virtual_size_max", "segments_virtual_size_avg",
    "has_text_segment", "has_data_segment", "has_linkedit_segment", "has_pagezero_segment", "has_objc_segment", "has_imports_segment",
    "has_text_section", "has_data_section", "has_bss_section", "has_la_symbol_ptr_section", "has_dylb_section", "has_cstring_section",
    "has_const_section", "has_literal4_section", "has_literal8_section", "has_jump_table_section", "has_pointers_section"
]

BYTE_BASED_FEATURES = [f"bigram_{i}" for i in range(128)] + [f"byte_hist_{i}" for i in range(256)]

STRING_FEATURES = ["fs_count", "network_count", "b64_count", "imported_libs_count", "funcs_count"]

PACKING_FEATURES = ["packing_suspicious_names", "packing_high_entropy"]

PERSISTENCE_FEATURES = ["persistence_login_items", "persistence_launch_items"]

API_FEATURES = get_api_names()

CERTIFICATES_FEATURES = ['cert_present', 'cert_expired', 'cert_self_signed', 'cert_revoked', 'cert_validated']


def parse_symbol(symbol):
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
    return symbol


# is_base64 now lives in macskillet.common.strings (imported above) so the ML
# vector and the agent findings share one definition of 'looks encoded'.


def get_shannon_entropy(bytez):

    entropy = 0
    for x in collections.Counter(bytearray(bytez)).values():
        p_x = float(x) / len(bytez)
        entropy -= p_x * np.log2(p_x)

    return entropy


class MachoFeatures:
    def extract_features(self, binaries, bytez):
        raise NotImplementedError("This method must be implemented")


class BytesNgrams:
    def __init__(self, n, num_features=128):
        self.n = n
        self.num_features = num_features

    def extract_features(self, bytez):
        """
        A binary consists in a sequence of bytes. Hence the vocabulary is V = {0, ..., 225}, |V| = 256.
        In general, the total number of N-grams is |V|^N.
        For N = 2, we can construct a matrix |V| x |V| and each possible 2-gram (x, y) in the matrix 
        can be identified with the following (hash) value: hash[(x, y)] = x * |V| + y = x * 256 + y.
        This approach can be extended to the N-dim space and we can assign a unique id to each value of this space.
        At this point, we can compute the N-grams of the bytes in the given section and then the corresponding
        vector representation.
        Finally, in order to compute a fixed-size representation for each section (note that each section has an
        arbitray number of n-grams), we can use the feature hashing trick.
        """
        vocabulary = {ngram: idx for idx, ngram in enumerate(itertools.product(list(range(256)), repeat=self.n))}
        ngrams_section = [tuple(bytez[i:i+self.n]) for i in range(len(bytez) - self.n + 1)]
        feature_map = {str(vocabulary[ngram]): vocabulary[ngram] for ngram in ngrams_section}
        feat_hasher = FeatureHasher(self.num_features)
        return feat_hasher.transform([feature_map]).toarray()[0]


class BytesFeatures(MachoFeatures):
    def compute_bigrams(self, bytez):
        bytes_ngram_extractor = BytesNgrams(n=2, num_features=128)
        return bytes_ngram_extractor.extract_features(bytez)

    def compute_bytes_histogram(self, bytez):
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).astype(np.float32)
        normalized = counts / counts.sum()
        return normalized

    def extract_features(self, binaries, bytez):
        bigram_feat = self.compute_bigrams(bytez)
        bytes_histogram_feat = self.compute_bytes_histogram(bytez)

        return np.concatenate([bigram_feat, bytes_histogram_feat])


class StringFeatures(MachoFeatures):
    """Numeric string features for the classical-ML baseline.

    Pattern matching is delegated to :mod:`macskillet.common.strings` — the same
    table the agent pipeline reasons over — so the ML vector and the agent's
    findings can never disagree about what counts as suspicious. This class
    reduces those matches to counts; use
    :func:`macskillet.common.strings.extract_strings_of_interest` when the
    string *values* are needed.
    """

    #: Categories exposed as dedicated vector components, in fixed order.
    #: Appending here changes the feature vector width — retrain downstream models.
    COUNT_CATEGORIES = ("filesystem_path", "network", "possible_base64")

    def extract_features(self, binaries, bytez):
        counts = count_categories(iter_strings(bytez))
        count_fs = counts.get("filesystem_path", 0)
        count_network = counts.get("network", 0)
        count_b64_chunks = counts.get("possible_base64", 0)

        imported_functions = set()
        imported_libs = set()
        # exports = ""
        for binary in binaries:
            for func in binary.imported_functions:
                try:
                    func_name = func.name.decode('utf-8') if isinstance(func.name, bytes) else func.name
                except Exception:
                    continue
                if func_name != "":
                    func_name = parse_symbol(func_name)
                    if func_name == "" or func_name.startswith("$s") or func_name.startswith("$S") or func_name.startswith("T0") or \
                            func_name.startswith("ZN") or func_name.startswith("ZT") or func_name.startswith("ZL") or func_name.startswith("ZZ") or \
                            func_name.startswith("symbolic ") or func_name.startswith("ZSVN") or func_name.startswith("OBJC_IVAR_") or \
                            func_name.startswith("associated ") or func_name.startswith("OBJC_PROTOCOL_"):
                        continue
                    imported_functions.add(func_name)
            for lib in binary.libraries:
                if lib.name != "":
                    imported_libs.add(lib.name)

        count_imported_libs = len(imported_libs)
        count_imported_funcs = len(imported_functions)

        return np.array([count_fs, count_network, count_b64_chunks, count_imported_libs, count_imported_funcs])


class StructualFeatures(MachoFeatures):
    def extract_features(self, binaries, bytez, mode='fat_merge'):
        assert mode in ['fat_merge', 'fat_union']
        if mode == 'fat_merge':
            return self._get_structural_features_fat_merge(binaries, bytez)
        else:
            return self._get_structural_features_fat_union(binaries, bytez)

    def _get_stats_binary(self, binary, target='segments'):
        def get_min_max_mean(data):
            try:
                return np.min(data), np.max(data), np.mean(data)
            except Exception:
                return 0, 0, 0

        if target == 'sections':
            target_data = binary.sections
            data_attr = 'content'
        elif target == 'load_commands':
            target_data = binary.commands
            data_attr = 'data'
        else:  # target == 'segments'
            target_data = binary.segments
            data_attr = 'content'

        stats = {
            "size": [],
            "entropy": [],
            "virtual_size": []
        }
        for obj in target_data:
            if hasattr(obj, data_attr):
                size = len(getattr(obj, data_attr))
                entropy = get_shannon_entropy(getattr(obj, data_attr))
            else:
                size = 0
                entropy = 0
            if target == 'segments':
                virtual_size = obj.virtual_size

            stats["size"].append(size)
            stats["entropy"].append(entropy)
            if target == 'segments':
                stats["virtual_size"].append(virtual_size)

        size_min, size_max, size_avg = get_min_max_mean(stats["size"])
        entropy_min, entropy_max, entropy_avg = get_min_max_mean(stats["entropy"])
        if target == 'segments':
            virtual_size_min, virtual_size_max, virtual_size_avg = get_min_max_mean(stats["virtual_size"])

        if target == 'segments':
            return size_min, size_max, size_avg, entropy_min, entropy_max, entropy_avg, virtual_size_min, virtual_size_max, virtual_size_avg
        else:
            return size_min, size_max, size_avg, entropy_min, entropy_max, entropy_avg

    def _get_structural_features_binary(self, binary, bytez):
        """
        - counter of (most common) load commands: how many load commands for each type
        - total size
        - number of sections for each segment
        - Stats about sections:
          * min, max, avg size of sections
          * min, max, avg entropy of sections
        - Stas about load commands:
          * min, max, avg size
          * min, max, avg entropy
          * min, max, avg virtual size
        - Stats about segments:
          * min, max, avg size
          * min, max, avg entropy
          * min, max, avg virtual size
        """

        lc_counter = {
            "BUILD_VERSION": 0,
            "CODE_SIGNATURE": 0,
            "DATA_IN_CODE": 0,
            "DYLD_CHAINED_FIXUPS": 0,
            "DYLD_ENVIRONMENT": 0,
            "DYLD_EXPORTS_TRIE": 0,
            "DYLD_INFO": 0,
            "DYLD_INFO_ONLY": 0,
            "DYLIB_CODE_SIGN_DRS": 0,
            "DYSYMTAB": 0,
            "ENCRYPTION_INFO": 0,
            "ENCRYPTION_INFO_64": 0,
            "FILESET_ENTRY": 0,
            "FUNCTION_STARTS": 0,
            "FVMFILE": 0,
            "IDENT": 0,
            "IDFVMLIB": 0,
            "ID_DYLIB": 0,
            "ID_DYLINKER": 0,
            "LAZY_LOAD_DYLIB": 0,
            "LINKER_OPTIMIZATION_HINT": 0,
            "LINKER_OPTION": 0,
            "LOADFVMLIB": 0,
            "LOAD_DYLIB": 0,
            "LOAD_DYLINKER": 0,
            "LOAD_UPWARD_DYLIB": 0,
            "LOAD_WEAK_DYLIB": 0,
            "MAIN": 0,
            "NOTE": 0,
            "PREBIND_CKSUM": 0,
            "PREBOUND_DYLIB": 0,
            "PREPAGE": 0,
            "REEXPORT_DYLIB": 0,
            "ROUTINES": 0,
            "ROUTINES_64": 0,
            "RPATH": 0,
            "SEGMENT": 0,
            "SEGMENT_64": 0,
            "SEGMENT_SPLIT_INFO": 0,
            "SOURCE_VERSION": 0,
            "SUB_CLIENT": 0,
            "SUB_FRAMEWORK": 0,
            "SUB_LIBRARY": 0,
            "SUB_UMBRELLA": 0,
            "SYMSEG": 0,
            "SYMTAB": 0,
            "THREAD": 0,
            "TWOLEVEL_HINTS": 0,
            "UNIXTHREAD": 0,
            "UUID": 0
        }

        for lc in binary.commands:
            try:
                lc_type = str(lc.command).split('.')[-1]
            except Exception:
                continue
            if lc_type in lc_counter.keys():
                lc_counter[lc_type] += 1

        size = len(bytez)
        virtual_size = binary.virtual_size
        # entropy = get_shannon_entropy(bytez)

        # features related to sections
        section_size_min, section_size_max, section_size_avg, \
            section_entropy_min, section_entropy_max, section_entropy_avg = self._get_stats_binary(binary, 'sections')
        # features related to load commands
        lc_size_min, lc_size_max, lc_size_avg, lc_entropy_min, lc_entropy_max, lc_entropy_avg = self._get_stats_binary(binary, 'load_commands')
        # features related to segments
        segments_size_min, segments_size_max, segments_size_avg, \
            segments_entropy_min, segments_entropy_max, segments_entropy_avg, \
            segments_virtual_size_min, segments_virtual_size_max, segments_virtual_size_avg = self._get_stats_binary(binary, 'segments')

        has_text_segment = binary.has_segment("__TEXT")
        has_data_segment = binary.has_segment("__DATA")
        has_linkedit_segment = binary.has_segment("__LINKEDIT")
        has_pagezero_segment = binary.has_segment("__PAGEZERO")
        has_objc_segment = binary.has_segment("__OBJC")
        has_imports_segment = binary.has_segment("__IMPORT")

        has_text_section = binary.has_section("__text")
        has_data_section = binary.has_section("__data")
        has_bss_section = binary.has_section("__bss")
        has_la_symbol_ptr_section = binary.has_section("__la_symbol_ptr")
        has_dylb_section = binary.has_section("__dylb")
        has_cstring_section = binary.has_section("__cstring")
        has_const_section = binary.has_section("__const")
        has_literal4_section = binary.has_section("__literal4")
        has_literal8_section = binary.has_section("__literal8")
        has_jump_table_section = binary.has_section("__jump_table")
        has_pointers_section = binary.has_section("__pointers")

        return np.array([
            size, virtual_size,
            *list(lc_counter.values()),
            section_size_min, section_size_max, section_size_avg,
            section_entropy_min, section_entropy_max, section_entropy_avg,
            lc_size_min, lc_size_max, lc_size_avg,
            lc_entropy_min, lc_entropy_max, lc_entropy_avg,
            segments_size_min, segments_size_max, segments_size_avg,
            segments_entropy_min, segments_entropy_max, segments_entropy_avg,
            segments_virtual_size_min, segments_virtual_size_max, segments_virtual_size_avg,
            has_text_segment, has_data_segment, has_linkedit_segment, has_pagezero_segment, has_objc_segment, has_imports_segment,
            has_text_section, has_data_section, has_bss_section, has_la_symbol_ptr_section, has_dylb_section, has_cstring_section,
            has_const_section, has_literal4_section, has_literal8_section, has_jump_table_section, has_pointers_section
        ])

    def _get_structural_features_fat_merge(self, binaries, bytez):
        lc_counter = {
            "BUILD_VERSION": 0,
            "CODE_SIGNATURE": 0,
            "DATA_IN_CODE": 0,
            "DYLD_CHAINED_FIXUPS": 0,
            "DYLD_ENVIRONMENT": 0,
            "DYLD_EXPORTS_TRIE": 0,
            "DYLD_INFO": 0,
            "DYLD_INFO_ONLY": 0,
            "DYLIB_CODE_SIGN_DRS": 0,
            "DYSYMTAB": 0,
            "ENCRYPTION_INFO": 0,
            "ENCRYPTION_INFO_64": 0,
            "FILESET_ENTRY": 0,
            "FUNCTION_STARTS": 0,
            "FVMFILE": 0,
            "IDENT": 0,
            "IDFVMLIB": 0,
            "ID_DYLIB": 0,
            "ID_DYLINKER": 0,
            "LAZY_LOAD_DYLIB": 0,
            "LINKER_OPTIMIZATION_HINT": 0,
            "LINKER_OPTION": 0,
            "LOADFVMLIB": 0,
            "LOAD_DYLIB": 0,
            "LOAD_DYLINKER": 0,
            "LOAD_UPWARD_DYLIB": 0,
            "LOAD_WEAK_DYLIB": 0,
            "MAIN": 0,
            "NOTE": 0,
            "PREBIND_CKSUM": 0,
            "PREBOUND_DYLIB": 0,
            "PREPAGE": 0,
            "REEXPORT_DYLIB": 0,
            "ROUTINES": 0,
            "ROUTINES_64": 0,
            "RPATH": 0,
            "SEGMENT": 0,
            "SEGMENT_64": 0,
            "SEGMENT_SPLIT_INFO": 0,
            "SOURCE_VERSION": 0,
            "SUB_CLIENT": 0,
            "SUB_FRAMEWORK": 0,
            "SUB_LIBRARY": 0,
            "SUB_UMBRELLA": 0,
            "SYMSEG": 0,
            "SYMTAB": 0,
            "THREAD": 0,
            "TWOLEVEL_HINTS": 0,
            "UNIXTHREAD": 0,
            "UUID": 0
        }

        size = len(bytez)
        # entropy = get_shannon_entropy(bytez)
        virtual_size = 0

        # header flags 
        header_flags = {
            'ALLMODSBOUND': 0,
            'ALLOW_STACK_EXECUTION': 0,
            'APP_EXTENSION_SAFE': 0,
            'BINDATLOAD': 0,
            'BINDS_TO_WEAK': 0,
            'CANONICAL': 0,
            'DEAD_STRIPPABLE_DYLIB': 0,
            'DYLDLINK': 0,
            'FORCE_FLAT': 0,
            'HAS_TLV_DESCRIPTORS': 0,
            'INCRLINK': 0,
            'LAZY_INIT': 0,
            'NOFIXPREBINDING': 0,
            'NOMULTIDEFS': 0,
            'NOUNDEFS': 0,
            'NO_HEAP_EXECUTION': 0,
            'NO_REEXPORTED_DYLIBS': 0,
            'PIE': 0,
            'PREBINDABLE': 0,
            'PREBOUND': 0,
            'ROOT_SAFE': 0,
            'SETUID_SAFE': 0,
            'SPLIT_SEGS': 0,
            'SUBSECTIONS_VIA_SYMBOLS': 0,
            'TWOLEVEL': 0,
            'WEAK_DEFINES': 0
        }

        # sections
        section_size_min_fat = []
        section_size_max_fat = []
        section_size_avg_fat = []
        section_entropy_min_fat = []
        section_entropy_max_fat = []
        section_entropy_avg_fat = []
        # load commands
        lc_size_min_fat = []
        lc_size_max_fat = []
        lc_size_avg_fat = []
        lc_entropy_min_fat = []
        lc_entropy_max_fat = []
        lc_entropy_avg_fat = []
        # segments
        segments_size_min_fat = []
        segments_size_max_fat = []
        segments_size_avg_fat = []
        segments_entropy_min_fat = []
        segments_entropy_max_fat = []
        segments_entropy_avg_fat = []
        segments_virtual_size_min_fat = []
        segments_virtual_size_max_fat = []
        segments_virtual_size_avg_fat = []

        has_text_segment = False
        has_data_segment = False
        has_linkedit_segment = False
        has_pagezero_segment = False
        has_objc_segment = False
        has_imports_segment = False

        has_text_section = False
        has_data_section = False
        has_bss_section = False
        has_la_symbol_ptr_section = False
        has_dylb_section = False
        has_cstring_section = False
        has_const_section = False
        has_literal4_section = False
        has_literal8_section = False
        has_jump_table_section = False
        has_pointers_section = False
        
        for binary in binaries:
            for lc in binary.commands:
                try:
                    lc_type = str(lc.command).split('.')[-1]
                except Exception:
                    continue
                if lc_type in lc_counter.keys():
                    lc_counter[lc_type] += 1

            virtual_size += binary.virtual_size

            # add header flags
            for flag in binary.header.flags_list:
                flag_name = str(flag).split('.')[-1]
                if flag_name in header_flags:
                    header_flags[flag_name] = 1

            # features related to sections
            section_size_min, section_size_max, section_size_avg, \
                section_entropy_min, section_entropy_max, section_entropy_avg = self._get_stats_binary(binary, 'sections')
            section_size_min_fat.append(section_size_min)
            section_size_max_fat.append(section_size_max)
            section_size_avg_fat.append(section_size_avg)
            section_entropy_min_fat.append(section_entropy_min)
            section_entropy_max_fat.append(section_entropy_max)
            section_entropy_avg_fat.append(section_entropy_avg)
            # features related to load commands
            lc_size_min, lc_size_max, lc_size_avg, lc_entropy_min, lc_entropy_max, lc_entropy_avg = self._get_stats_binary(binary, 'load_commands')
            lc_size_min_fat.append(lc_size_min)
            lc_size_max_fat.append(lc_size_max)
            lc_size_avg_fat.append(lc_size_avg)
            lc_entropy_min_fat.append(lc_entropy_min)
            lc_entropy_max_fat.append(lc_entropy_max)
            lc_entropy_avg_fat.append(lc_entropy_avg)
            # features related to segments
            segments_size_min, segments_size_max, segments_size_avg, \
                segments_entropy_min, segments_entropy_max, segments_entropy_avg, \
                segments_virtual_size_min, segments_virtual_size_max, segments_virtual_size_avg = self._get_stats_binary(binary, 'segments')
            segments_size_min_fat.append(segments_size_min)
            segments_size_max_fat.append(segments_size_max)
            segments_size_avg_fat.append(segments_size_avg)
            segments_entropy_min_fat.append(segments_entropy_min)
            segments_entropy_max_fat.append(segments_entropy_max)
            segments_entropy_avg_fat.append(segments_entropy_avg)
            segments_virtual_size_min_fat.append(segments_virtual_size_min)
            segments_virtual_size_max_fat.append(segments_virtual_size_max)
            segments_virtual_size_avg_fat.append(segments_virtual_size_avg)

            has_text_segment |= binary.has_segment("__TEXT")
            has_data_segment = binary.has_segment("__DATA")
            has_linkedit_segment = binary.has_segment("__LINKEDIT")
            has_pagezero_segment = binary.has_segment("__PAGEZERO")
            has_objc_segment = binary.has_segment("__OBJC")
            has_imports_segment = binary.has_segment("__IMPORT")

            has_text_section |= binary.has_section("__text")
            has_data_section |= binary.has_section("__data")
            has_bss_section |= binary.has_section("__bss")
            has_la_symbol_ptr_section |= binary.has_section("__la_symbol_ptr")
            has_dylb_section |= binary.has_section("__dylb")
            has_cstring_section |= binary.has_section("__cstring")
            has_const_section |= binary.has_section("__const")
            has_literal4_section |= binary.has_section("__literal4")
            has_literal8_section |= binary.has_section("__literal8")
            has_jump_table_section |= binary.has_section("__jump_table")
            has_pointers_section |= binary.has_section("__pointers")

        section_size_min, section_size_max, section_size_avg = np.min(section_size_min_fat), np.max(section_size_max_fat), np.mean(section_size_avg_fat)
        section_entropy_min, section_entropy_max, section_entropy_avg = np.min(section_entropy_min_fat), np.max(section_entropy_max_fat), np.mean(section_entropy_avg_fat)
        lc_size_min, lc_size_max, lc_size_avg = np.min(lc_size_min_fat), np.max(lc_size_max_fat), np.mean(lc_size_avg_fat)
        lc_entropy_min, lc_entropy_max, lc_entropy_avg = np.min(lc_entropy_min_fat), np.max(lc_entropy_max_fat), np.mean(lc_entropy_avg_fat)
        segments_size_min, segments_size_max, segments_size_avg = np.min(segments_size_min_fat), np.max(segments_size_max_fat), np.mean(segments_size_avg_fat)
        segments_entropy_min, segments_entropy_max, segments_entropy_avg = np.min(segments_entropy_min_fat), np.max(segments_entropy_max_fat), np.mean(segments_entropy_avg_fat)
        segments_virtual_size_min, segments_virtual_size_max, segments_virtual_size_avg = np.min(segments_virtual_size_min_fat), np.max(segments_virtual_size_max_fat), np.mean(segments_virtual_size_avg_fat)

        return np.array([
            size, virtual_size,
            *list(header_flags.values()),
            *list(lc_counter.values()),
            section_size_min, section_size_max, section_size_avg,
            section_entropy_min, section_entropy_max, section_entropy_avg,
            lc_size_min, lc_size_max, lc_size_avg,
            lc_entropy_min, lc_entropy_max, lc_entropy_avg,
            segments_size_min, segments_size_max, segments_size_avg,
            segments_entropy_min, segments_entropy_max, segments_entropy_avg,
            segments_virtual_size_min, segments_virtual_size_max, segments_virtual_size_avg,
            has_text_segment, has_data_segment, has_linkedit_segment, has_pagezero_segment, has_objc_segment, has_imports_segment,
            has_text_section, has_data_section, has_bss_section, has_la_symbol_ptr_section, has_dylb_section, has_cstring_section,
            has_const_section, has_literal4_section, has_literal8_section, has_jump_table_section, has_pointers_section
        ]).astype(np.float32)

    def _get_structural_features_fat_union(self, binaries, bytez):
        sha256 = hashlib.sha256(bytez).hexdigest()

        total_features = []
        for idx, binary in binaries:
            binary.write(f"{sha256}_{idx}")
            with open(f"{sha256}_{idx}", 'rb') as f:
                bytez_bin = f.read()
            features_binary = self._get_structural_features_binary(binary, bytez_bin)
            total_features.append(features_binary)
            os.remove(f"{sha256}_{idx}")

        return np.array(total_features).astype(np.float32)


class PersistenceFeatures(MachoFeatures):
    def check_persistence_login_items(self, binary):
        """
        Check if the binary has a persistence mechanism using login items.
        """
        # extract API calls
        create_found = False
        insert_found = False
        for symbol in binary.symbols:  # NOTE: maybe better to use imported_symbols?
            try:
                symbol_name_parsed = symbol.name.decode('utf-8') if isinstance(symbol.name, bytes) else symbol.name
            except Exception:
                continue
            if symbol_name_parsed == "":
                continue
            if re.search("SMLoginItemSetEnabled", symbol_name_parsed):  # new API
                insert_found = True
                create_found = True
                break
            if re.search("LSSharedFileListCreate", symbol_name_parsed):
                create_found = True
            if re.search("LSSharedFileListInsertItemURL", symbol_name_parsed):
                insert_found = True

        return int(create_found and insert_found)

    def check_persistence_launch_items(self, bytez):
        """
        Check if the binary has a persistence mechanism using launch items.
        """
        return 1 if re.search(b'<key>RunAtLoad</key>', bytez) else 0
    
    def extract_features(self, binaries, bytez):
        has_persistence_login_items = 0
        has_persistence_launch_items = 0

        for binary in binaries:
            has_persistence_login_items |= self.check_persistence_login_items(binary)
        
        has_persistence_launch_items = self.check_persistence_launch_items(bytez)

        return np.array([has_persistence_login_items, has_persistence_launch_items])


class CertInfoFeatures(MachoFeatures):
    """Certificate-chain features for the classical-ML baseline.

    Thin adapter over :func:`macskillet.machopy.code_signature_verifier.
    verify_code_signature`, which already performs real chain validation
    against pinned Apple roots (see that module). Replaces the former
    CertInfoExtractor, which reimplemented chain validation using three
    additional unmaintained dependencies (oscrypto, certvalidator,
    macholib), wrote per-arch temp files into the current working directory,
    had a validation result it computed and then discarded in favor of a
    forgeable "Apple Root CA" name-membership check, and referenced a
    ``certs/`` directory that never shipped with the package.
    """

    #: aligned with CERTIFICATES_FEATURES below -- order is the ML contract.
    FEATURE_NAMES = ("cert_present", "cert_expired", "cert_self_signed",
                     "cert_revoked", "cert_validated")

    def extract_features(self, binary_path, check_revocation: bool = False):
        result = verify_code_signature(binary_path, check_revocation=check_revocation)
        slices = [s for s in result["slices"].values() if s.get("signed")]

        cert_present = 1 if slices else 0
        # Conservative aggregation across architecture slices: a single bad
        # slice in a universal binary should not be averaged away by a good
        # one -- "any slice expired/self-signed/revoked" sets the flag, and
        # "validated" requires every present chain to validate.
        chains = [s["chain"] for s in slices if s.get("chain")]
        cert_expired = int(any(c.get("expired") for c in chains))
        cert_self_signed = int(any(c.get("self_signed") for c in chains))
        cert_revoked = int(any(c.get("revocation", {}).get("revoked") for c in chains))
        cert_validated = int(bool(chains) and all(c.get("valid") for c in chains))

        return np.array([cert_present, cert_expired, cert_self_signed,
                         cert_revoked, cert_validated])


class PackingFeatures(MachoFeatures):
    def extract_features(self, binaries, bytez):
        has_suspicious_segments_names = 0
        has_segments_packed = 0
        
        packed_data_size = 0
        for binary in binaries:
            # Features related to packing
            for segment in binary.segments:
                if re.search(SEGMENT_NAMES_PACKING_PATTERNS, segment.name, re.IGNORECASE):
                    has_suspicious_segments_names = 1
                    break

            for segment in binary.segments:
                segment_size = len(segment.content)
                if segment_size > 0:
                    entropy = get_shannon_entropy(segment.content)
                    if entropy > ENTROPY_THRESHOLD:
                        packed_data_size += segment_size

        if (packed_data_size / len(bytez)) > PACKING_RATIO_THRESHOLD:
            has_segments_packed = 1

        return np.array([has_suspicious_segments_names, has_segments_packed])


class EncryptionFeatures(MachoFeatures):
    def extract_features(self, binaries):
        is_encrypted = 0

        for binary in binaries:
            # Features related to encryption
            # NOTE: May be useful only for iOS binaries
            for segment in binary.segments:
                # check if the flag 0x8 (SG_PROTECTED_VERSION_1) is set using mask 0x8
                if segment.flags & 0x08:
                    is_encrypted = 1
                    break
            
            # check if there is a load command of type LC_ENCRYPTION_INFO or LC_ENCRYPTION_INFO_64 (for iOS)
            for lc in binary.commands:
                try:
                    lc_name = str(lc.command).split('.')[-1]
                except Exception:
                    continue
                if lc_name in ["ENCRYPTION_INFO", "ENCRYPTION_INFO_64"]:
                    is_encrypted = 1
                    break
    
        return np.array([is_encrypted])


class EntitlementsFeatures(MachoFeatures):
    def extract_features(self, binary_path, use_all_entitlements=False):
        return EntitlementsExtractor(use_all_entitlements=use_all_entitlements).extract_features(binary_path)


class APIFeatures(MachoFeatures):
    def extract_features(self, binary_path):
        return APIExtractor().extract_features(binary_path)


def extract_features_binary(binary_path, label, features_selector, mode):
    def _signal_handler(signum, frame):
        raise TimeoutError()

    # Timeout setup
    signal.signal(signal.SIGALRM, _signal_handler)
    signal.alarm(TIMEOUT_DEFAULT)

    # print(f"Extracting features for: {binary_path}")

    try:
        fat_binary = lief.MachO.parse(binary_path)
    except TimeoutError:
        print(f"[WARN] Timeout error for {binary_path}")
        return np.array([])
    finally:
        signal.alarm(0)

    if fat_binary is None:
        return np.array([])
    binaries = [fat_binary.at(idx) for idx in range(fat_binary.size)]
    with open(binary_path, 'rb') as f:
        bytez = f.read()
    sha256 = hashlib.sha256(bytez).hexdigest()

    try:
        selected_features = np.array([])
        for feature_class in features_selector:
            if feature_class == 'structural':
                selected_features = np.concatenate([selected_features, StructualFeatures().extract_features(binaries, bytez, mode)])
            if feature_class == 'byte':
                selected_features = np.concatenate([selected_features, BytesFeatures().extract_features(binaries, bytez)])
            if feature_class == 'string':
                selected_features = np.concatenate([selected_features, StringFeatures().extract_features(binaries, bytez)])
            if feature_class == 'entitlements':
                selected_features = np.concatenate([selected_features, EntitlementsFeatures().extract_features(binary_path, use_all_entitlements=False)])
            elif feature_class == 'entitlements_all':
                selected_features = np.concatenate([selected_features, EntitlementsFeatures().extract_features(binary_path, use_all_entitlements=True)])
            if feature_class == 'packing':
                selected_features = np.concatenate([selected_features, PackingFeatures().extract_features(binaries, bytez)])
            if feature_class == 'persistence':
                selected_features = np.concatenate([selected_features, PersistenceFeatures().extract_features(binaries, bytez)])
            if feature_class == 'api':
                selected_features = np.concatenate([selected_features, APIFeatures().extract_features(binary_path)])
            if feature_class == 'certificates':
                selected_features = np.concatenate([selected_features, CertInfoFeatures().extract_features(binary_path)])
    except Exception as e:
        # print(f"[WARN] Error extracting features for {binary_path}: {e}")
        return np.array([])

    return np.concatenate([[sha256], selected_features, [label]])


class FeatureExtractorMacho:
    def __init__(self, n_jobs=None, mode='fat_merge', features_selector=None):
        assert n_jobs is None or (isinstance(n_jobs, int) and n_jobs > 0)
        assert mode in ['fat_merge', 'fat_union']
        if features_selector is None:
            features_selector = FEATURE_TYPES.copy().remove('entitlements_all')
        else:
            assert isinstance(features_selector, list) and len(features_selector) > 0
            assert all([feat in FEATURE_TYPES for feat in features_selector])
            assert len(features_selector) == len(set(features_selector))

        if n_jobs is None:
            n_jobs = len(os.sched_getaffinity(0)) - 1

        self.n_jobs = n_jobs
        self.mode = mode
        self.features_selector = features_selector

    def extract_features(self, samples_path, label):
        assert isinstance(label, int) or (isinstance(label, list) and len(label) == len(samples_path))
        labels = [label] * len(samples_path) if isinstance(label, int) else label
        modes = [self.mode] * len(samples_path)
        feat_type_samples = [self.features_selector] * len(samples_path)

        # results = Parallel(n_jobs=n_jobs, timeout=TIMEOUT_DEFAULT)(delayed(extract_features_sample)(package, y) for package, y in zip(packages, labels))
        with multiprocessing.Pool(processes=self.n_jobs) as pool:
            results = pool.starmap(extract_features_binary, zip(samples_path, labels, feat_type_samples, modes))
        results = [res for res in results if res.tolist() != []]

        # check if all the samples have the same number of features
        assert all([len(res) == len(results[0]) for res in results])

        # add column names
        columns = ['sha256']
        for feat_type in self.features_selector:
            if feat_type == 'structural':
                columns += STRUCTURAL_FEATURES
            if feat_type == 'byte':
                columns += BYTE_BASED_FEATURES
            if feat_type == 'string':
                columns += STRING_FEATURES
            if feat_type in {'entitlements', 'entitlements_all'}:
                entitlements_feature_names = ENTITLEMENTS_FEATURES_FINAL if feat_type == 'entitlements' else ENTITLEMENTS_FEATURES_ALL
                for entitlement in entitlements_feature_names:
                    col_name = "ent_"
                    if entitlement.startswith("com.apple.security"):
                        col_name += entitlement.replace("com.apple.security", "security")
                    elif entitlement.startswith("com.apple.developer"):
                        col_name += entitlement.replace("com.apple.developer", "developer")
                    elif entitlement.startswith("com.apple.private"):
                        col_name += entitlement.replace("com.apple.private", "private")
                    elif entitlement.startswith("com.apple.vm"):
                        col_name += entitlement.replace("com.apple.vm", "vm")
                    elif entitlement.startswith("com.apple"):
                        col_name += entitlement.replace("com.apple", "generic")
                    else:
                        col_name += entitlement
                    columns.append(col_name)
            if feat_type == 'packing':
                columns += PACKING_FEATURES
            if feat_type == 'persistence':
                columns += PERSISTENCE_FEATURES
            if feat_type == 'api':
                columns += API_FEATURES
            if feat_type == 'certificates':
                columns += CERTIFICATES_FEATURES
        columns.append("label")

        dataset = pd.DataFrame(data=results, columns=columns)
        assert not dataset.isnull().values.any()

        return dataset