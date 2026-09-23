"""Characterize application startup without live scans or an operator database.

Shutdown currently requests monitor cancellation; it does not await a graceful
join. The tests finish their own synthetic tasks so that limitation is explicit
without changing the application's scheduler behaviour.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app import dashboard


@pytest.fixture
def lifecycle_environment(tmp_path, monkeypatch):
    """Isolate every startup write and replace database/provider/monitor work."""
    directories = {
        "STATE": tmp_path / "state",
        "REPORTS_ROOT": tmp_path / "reports",
        "REPORTS": tmp_path / "reports" / "generated",
        "LOGS_ROOT": tmp_path / "logs",
    }
    for name, path in directories.items():
        monkeypatch.setattr(dashboard, name, path)

    database = Mock(spec=[
        "get_setting", "clear_scan_data", "set_setting", "add_managed_domain",
    ])
    database.get_setting.side_effect = lambda _name, default: default
    get_database = Mock(return_value=database)
    load_provider_settings = Mock(return_value=[])

    async def wait_for_shutdown():
        await asyncio.Future()

    monitor = AsyncMock(side_effect=wait_for_shutdown)
    create_task = Mock(wraps=asyncio.create_task)
    monkeypatch.setenv("NORTHFLUX_ENV", "development")
    monkeypatch.setenv("NORTHFLUX_DEMO_MODE", "false")
    monkeypatch.delenv("DASH_TOKEN", raising=False)
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "get_database", get_database)
    monkeypatch.setattr(dashboard, "_load_cf_runtime_settings", load_provider_settings)
    monkeypatch.setattr(dashboard, "_react_frontend_available", Mock(return_value=True))
    monkeypatch.setattr(dashboard, "_monitoring_loop", monitor)
    monkeypatch.setattr(dashboard, "_monitor_task", None)
    monkeypatch.setattr(dashboard.asyncio, "create_task", create_task)
    return SimpleNamespace(
        directories=directories,
        database=database,
        get_database=get_database,
        load_provider_settings=load_provider_settings,
        monitor=monitor,
        create_task=create_task,
    )


def test_one_monitor_is_scheduled_per_lifespan_and_cancelled_at_shutdown(
    lifecycle_environment,
):
    environment = lifecycle_environment

    async def exercise():
        previous_task = None
        for startup_count in (1, 2):
            async with dashboard.app.router.lifespan_context(dashboard.app):
                task = dashboard._monitor_task
                assert task is not previous_task
                assert environment.create_task.call_count == startup_count
                await asyncio.sleep(0)
                assert environment.monitor.await_count == startup_count
                assert not task.done()
                for directory in environment.directories.values():
                    assert directory.is_dir()
                assert (environment.directories["REPORTS_ROOT"] / "archive").is_dir()

            # Give the cancellation request a turn to reach the synthetic task.
            await asyncio.sleep(0)
            assert task.cancelled()
            previous_task = task

    asyncio.run(exercise())
    assert environment.get_database.call_count == 2
    assert environment.load_provider_settings.call_count == 2
    environment.load_provider_settings.assert_called_with(environment.database)


def test_shutdown_requests_cancellation_without_joining_monitor_cleanup(
    lifecycle_environment, monkeypatch,
):
    async def exercise():
        started = asyncio.Event()
        cancellation_received = asyncio.Event()
        release_cleanup = asyncio.Event()

        async def slow_cleanup_monitor():
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_received.set()
                await release_cleanup.wait()
                raise

        monkeypatch.setattr(dashboard, "_monitoring_loop", slow_cleanup_monitor)
        task = None
        try:
            async with dashboard.app.router.lifespan_context(dashboard.app):
                task = dashboard._monitor_task
                await asyncio.sleep(0)
                assert started.is_set()

            # Lifespan has already returned, although cancellation cleanup has
            # not run to completion. This is characterization, not a join promise.
            await asyncio.sleep(0)
            assert cancellation_received.is_set()
            assert not task.done()
        finally:
            release_cleanup.set()
            if task is not None:
                if not cancellation_received.is_set():
                    task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def bounded_exercise():
        # A future accidental join must fail this characterization rather than
        # deadlock waiting for the cleanup gate that only this test can release.
        await asyncio.wait_for(exercise(), timeout=5)

    asyncio.run(bounded_exercise())


@pytest.mark.parametrize(
    ("mode", "demo_mode"), [("development", "false"), ("production", "true")],
)
def test_default_startup_preserves_history_and_production_never_seeds_demo(
    lifecycle_environment, monkeypatch, mode, demo_mode,
):
    environment = lifecycle_environment
    monkeypatch.setenv("NORTHFLUX_ENV", mode)
    monkeypatch.setenv("NORTHFLUX_DEMO_MODE", demo_mode)
    monkeypatch.setenv("DASH_TOKEN", "synthetic-startup-token-with-32-characters")

    async def exercise():
        async with dashboard.app.router.lifespan_context(dashboard.app):
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert dashboard._monitor_task.cancelled()

    asyncio.run(exercise())
    environment.database.get_setting.assert_called_once_with("clear_on_start", "false")
    environment.database.clear_scan_data.assert_not_called()
    environment.database.set_setting.assert_not_called()
    environment.database.add_managed_domain.assert_not_called()
    environment.load_provider_settings.assert_called_once_with(environment.database)


def test_clear_on_start_remains_an_explicit_opt_in_in_production(
    lifecycle_environment, monkeypatch,
):
    environment = lifecycle_environment
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.setenv("DASH_TOKEN", "synthetic-startup-token-with-32-characters")
    environment.database.get_setting.side_effect = None
    environment.database.get_setting.return_value = "true"

    async def exercise():
        async with dashboard.app.router.lifespan_context(dashboard.app):
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert dashboard._monitor_task.cancelled()

    asyncio.run(exercise())
    environment.database.clear_scan_data.assert_called_once_with()


@pytest.mark.parametrize(
    ("token", "frontend_available", "message"),
    [
        ("", True, "DASH_TOKEN is required"),
        ("short", True, "at least 32 characters"),
        ("synthetic-startup-token-with-32-characters", False, "compiled React frontend"),
    ],
)
def test_production_preflight_failure_does_not_start_runtime_work(
    lifecycle_environment, monkeypatch, token, frontend_available, message,
):
    environment = lifecycle_environment
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.setenv("DASH_TOKEN", token)
    monkeypatch.setattr(
        dashboard, "_react_frontend_available", Mock(return_value=frontend_available),
    )

    async def exercise():
        with pytest.raises(RuntimeError, match=message):
            async with dashboard.app.router.lifespan_context(dashboard.app):
                pytest.fail("Invalid production configuration must not enter lifespan")

    asyncio.run(exercise())
    environment.get_database.assert_not_called()
    environment.load_provider_settings.assert_not_called()
    environment.monitor.assert_not_called()
    environment.create_task.assert_not_called()
    assert dashboard._monitor_task is None
    assert all(not path.exists() for path in environment.directories.values())
