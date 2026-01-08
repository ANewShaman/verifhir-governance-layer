import signal
import sys
import logging
import threading
from contextlib import contextmanager

logger = logging.getLogger("verifhir.runtime")


class GracefulShutdown(Exception):
    pass


def _signal_handler(signum, frame):
    raise GracefulShutdown(f"Received signal {signum}")


def install_signal_handlers():
    """
    Install signal handlers safely.

    On some platforms (or when running in a non-main thread, e.g. Streamlit worker
    threads), calling signal.signal will raise. Make this function resilient so
    imports won't fail.
    """
    try:
        # Only install handlers from the main thread
        if threading.current_thread() is not threading.main_thread():
            logger.debug("Not main thread; skipping signal handler installation")
            return

        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, _signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _signal_handler)
    except (ValueError, AttributeError) as e:
        # ValueError: signal only works in main thread
        # AttributeError: SIGTERM may not exist on some platforms
        logger.warning(f"Could not install signal handlers: {e}")
    except Exception:
        logger.exception("Unexpected failure installing signal handlers")


def _safe_flush():
    try:
        # telemetry flush hook (noop for now)
        pass
    except Exception:
        pass


def _safe_ui_exit(message: str):
    try:
        import streamlit as st
        st.warning(message)
        st.stop()
    except Exception:
        pass


def _handle_runtime_failure(e: Exception):
    try:
        logger.error("Runtime failure", exc_info=False)
        _safe_ui_exit("An internal error occurred. No data was saved.")
    except Exception:
        pass


@contextmanager
def graceful_execution_context():
    try:
        yield
    except GracefulShutdown:
        logger.info("Graceful shutdown initiated")
        _safe_flush()
        _safe_ui_exit("Session ended safely.")
        sys.exit(0)
    except Exception as e:
        _handle_runtime_failure(e)
    finally:
        _safe_flush()
