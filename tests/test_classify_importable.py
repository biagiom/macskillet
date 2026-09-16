import sys
import os
import pytest



def test_classify_bundle_importable_without_anthropic():
    """common/report.py must be importable even when the anthropic SDK is absent.

    This is a regression guard against reintroducing a top-level `import anthropic`
    into a module `cli.py` imports unconditionally on every classify run.
    """
    saved = sys.modules.get('anthropic', '__MISSING__')
    # Setting sys.modules[name] = None causes ModuleNotFoundError on any import of that name.
    sys.modules['anthropic'] = None
    sys.modules.pop('macskillet.common.report', None)

    try:
        import macskillet.common.report  # noqa: F401
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.fail(
            f"common/report.py raised {type(exc).__name__} without anthropic: {exc}"
        )
    finally:
        sys.modules.pop('macskillet.common.report', None)
        if saved == '__MISSING__':
            sys.modules.pop('anthropic', None)
        else:
            sys.modules['anthropic'] = saved
