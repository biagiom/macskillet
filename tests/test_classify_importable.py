import sys
import os
import pytest



def test_classify_bundle_importable_without_anthropic():
    """classify_bundle_native must be importable even when the anthropic SDK is absent.

    This exercises --features-only and --local modes which don't use the Claude API.
    """
    saved = sys.modules.get('anthropic', '__MISSING__')
    # Setting sys.modules[name] = None causes ModuleNotFoundError on any import of that name.
    sys.modules['anthropic'] = None
    sys.modules.pop('macskillet.native.classify_bundle_native', None)

    try:
        import macskillet.native.classify_bundle_native  # noqa: F401
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.fail(
            f"classify_bundle_native raised {type(exc).__name__} without anthropic: {exc}"
        )
    finally:
        sys.modules.pop('macskillet.native.classify_bundle_native', None)
        if saved == '__MISSING__':
            sys.modules.pop('anthropic', None)
        else:
            sys.modules['anthropic'] = saved
