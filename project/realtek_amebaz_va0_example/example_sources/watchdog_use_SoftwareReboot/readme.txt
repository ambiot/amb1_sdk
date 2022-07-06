Example Description

This example describes how to use software reboot in watchdog irq handler.

Requirement Components: None

In this example, watchdog is setup to 5s timeout.

When watchdog barks, software_reboot() will be called and the GPIO pin voltage won't change during rebooting.
