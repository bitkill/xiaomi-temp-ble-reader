"""An abstract class for entities."""

from abc import ABC
import asyncio
from datetime import datetime, timedelta
import const
from typing import Any, Awaitable, Dict, List, Optional, Callable, Union

CALLBACK_TYPE = Callable[[], None]
StateType = Union[None, str, int, float]

SLOW_UPDATE_WARNING = 10
DATA_ENTITY_SOURCE = "entity_info"
SOURCE_CONFIG_ENTRY = "config_entry"
SOURCE_PLATFORM_CONFIG = "platform_config"


class Entity(ABC):
    """An abstract class for Home Assistant entities."""

    # SAFE TO OVERWRITE
    # The properties and methods here are safe to overwrite when inheriting
    # this class. These may be used to customize the behavior of the entity.
    entity_id = None  # type: str

    # If we reported if this entity was slow
    _slow_reported = False

    # If we reported this entity is updated while disabled
    _disabled_reported = False

    # Protect for multiple updates
    _update_staged = False

    # Process updates in parallel
    parallel_updates: Optional[asyncio.Semaphore] = None

    # Entry in the entity registry
    registry_entry: Optional[Dict] = None

    # Hold list for functions to call on remove.
    _on_remove: Optional[List[CALLBACK_TYPE]] = None

    # If entity is added to an entity platform
    _added = False

    @property
    def should_poll(self) -> bool:
        """Return True if entity has to be polled for state.

        False if entity pushes its state to HA.
        """
        return True

    @property
    def unique_id(self) -> Optional[str]:
        """Return a unique ID."""
        return None

    @property
    def name(self) -> Optional[str]:
        """Return the name of the entity."""
        return None

    @property
    def state(self) -> StateType:
        """Return the state of the entity."""
        return const.STATE_UNKNOWN

    @property
    def capability_attributes(self) -> Optional[Dict[str, Any]]:
        """Return the capability attributes.

        Attributes that explain the capabilities of an entity.

        Implemented by component base class. Convention for attribute names
        is lowercase snake_case.
        """
        return None

    @property
    def state_attributes(self) -> Optional[Dict[str, Any]]:
        """Return the state attributes.

        Implemented by component base class. Convention for attribute names
        is lowercase snake_case.
        """
        return None

    @property
    def device_state_attributes(self) -> Optional[Dict[str, Any]]:
        """Return device specific state attributes.

        Implemented by platform classes. Convention for attribute names
        is lowercase snake_case.
        """
        return None

    @property
    def device_info(self) -> Optional[Dict[str, Any]]:
        """Return device specific attributes.

        Implemented by platform classes.
        """
        return None

    @property
    def device_class(self) -> Optional[str]:
        """Return the class of this device, from component DEVICE_CLASSES."""
        return None

    @property
    def unit_of_measurement(self) -> Optional[str]:
        """Return the unit of measurement of this entity, if any."""
        return None

    @property
    def icon(self) -> Optional[str]:
        """Return the icon to use in the frontend, if any."""
        return None

    @property
    def entity_picture(self) -> Optional[str]:
        """Return the entity picture to use in the frontend, if any."""
        return None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return True

    @property
    def assumed_state(self) -> bool:
        """Return True if unable to access real state of the entity."""
        return False

    @property
    def force_update(self) -> bool:
        """Return True if state updates should be forced.

        If True, a state change will be triggered anytime the state property is
        updated, not just when the value changes.
        """
        return False

    @property
    def supported_features(self) -> Optional[int]:
        """Flag supported features."""
        return None

    @property
    def context_recent_time(self) -> timedelta:
        """Time that a context is considered recent."""
        return timedelta(seconds=5)

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added to the entity registry."""
        return True

    # DO NOT OVERWRITE
    # These properties and methods are either managed by Home Assistant or they
    # are used to perform a very specific function. Overwriting these may
    # produce undesirable effects in the entity's operation.

    @property
    def enabled(self) -> bool:
        """Return if the entity is enabled in the entity registry.

        If an entity is not part of the registry, it cannot be disabled
        and will therefore always be enabled.
        """
        return self.registry_entry is None or not self.registry_entry.disabled

    def __eq__(self, other: Any) -> bool:
        """Return the comparison."""
        if not isinstance(other, self.__class__):
            return False

        # Can only decide equality if both have a unique id
        if self.unique_id is None or other.unique_id is None:
            return False

        return self.unique_id == other.unique_id

    def __repr__(self) -> str:
        """Return the representation."""
        return f"<Entity {self.name}: {self.state}>"

    async def async_request_call(self, coro: Awaitable) -> None:
        """Process request batched."""
        if self.parallel_updates:
            await self.parallel_updates.acquire()

        try:
            await coro
        finally:
            if self.parallel_updates:
                self.parallel_updates.release()


class BinarySensorEntity(Entity):
    """Represent a binary sensor."""

    @property
    def is_on(self):
        """Return true if the binary sensor is on."""
        return None

    @property
    def state(self):
        """Return the state of the binary sensor."""
        return const.STATE_ON if self.is_on else const.STATE_OFF

    @property
    def device_class(self):
        """Return the class of this device, from component DEVICE_CLASSES."""
        return None
