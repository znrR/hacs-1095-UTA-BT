"""Output datapoints, status bits and installation-specific group addresses.

The hex strings are decrypted telegrams recorded from a second 1095 UTA-BT
installation (group addresses differ from the original one). No BLE is used.
"""

import asyncio

import pytest

from custom_components.busch_jaeger_1095_bt import protocol as bt

# Room temperature 22.14 C on group B94B, pushed about once per second.
ROOM = "830102000d0011003ce00201b94b0378800c53"
# Offset +0.5 (AE28), setpoint 23.0 (4D57), actuating value 0x6c (E7EF).
SETPOINT_UP = "830102001a0011003ce00201ae2803188000324d57031c800c7ee7ef0220806c"
# Eco: offset 0, effective setpoint 19.0, actuating 0, status 0x64 (AFC6).
ECO = "83010200200011003ce00201ae2803a08000004d5703a480076ce7ef02a88000afc602ac8064"

GROUPS = {
    0xB94B: "measured_temperature",
    0x4D57: "setpoint",
    0xAE28: "relative_setpoint",
    0xE7EF: "actuating_value_heating",
    0xAFC6: "status",
}


def test_output_read_frame_matches_setpoint_read():
    assert bt.output_read(2) == bt.setpoint_read()
    assert bt.output_read(9).hex() == "11000400fff002010902c700df000103000109"
    with pytest.raises(ValueError):
        bt.output_read(0)


def test_decode_values():
    assert bt.decode_value("temperature", bytes.fromhex("0c53")) == 22.14
    assert bt.decode_value("temperature", bytes.fromhex("02bc")) == 7.0
    assert bt.decode_value("temperature", bytes.fromhex("87ce")) == -0.5
    assert bt.decode_value("percent", bytes.fromhex("ff")) == 100.0
    assert bt.decode_value("percent", bytes.fromhex("2a")) == 16.5
    assert bt.decode_value("bool", b"\x00") is False
    assert bt.decode_value("temperature", b"\x01") is None


def test_status_bits():
    comfort_heating = bt.decode_status(0x21)
    assert comfort_heating["comfort"] and comfort_heating["heating_mode"]
    assert not comfort_heating["inactive"] and not comfort_heating["eco"]
    eco_idle = bt.decode_status(0x64)
    assert eco_idle["eco"] and eco_idle["inactive"] and not eco_idle["comfort"]
    assert bt.decode_status(0x61)["inactive"]


def test_default_groups_ignore_other_installations():
    assert bt.state_reports(bytes.fromhex(ROOM)) == []
    assert bt.group_telegrams(bytes.fromhex(ROOM)) == [(0xB94B, bytes.fromhex("0c53"))]


def test_custom_groups_decode_reports():
    room = bt.state_reports(bytes.fromhex(ROOM), GROUPS)
    assert room == [{"name": "measured_temperature", "value": 22.14, "group": "b94b"}]
    up = {r["name"]: r["value"] for r in bt.state_reports(bytes.fromhex(SETPOINT_UP), GROUPS)}
    assert up == {"relative_setpoint": 0.5, "setpoint": 23.0, "actuating_value_heating": 42.4}
    eco = {r["name"]: r["value"] for r in bt.state_reports(bytes.fromhex(ECO), GROUPS)}
    assert eco["setpoint"] == 19.0 and eco["status"] == 0x64


def test_unknown_groups_are_emitted_raw():
    events = []
    device = bt.Thermostat("AA:BB", bytes(32), on_event=events.append)
    plaintext = bytes.fromhex(ROOM)
    # _telegram receives the inner fragment, i.e. without the outer 83 0102 prefix.
    device._telegram(bytes.fromhex("03") + plaintext[3:])
    raw = [e for e in events if e["kind"] == "group_report"]
    assert raw and raw[0]["group"] == "b94b" and raw[0]["hex"] == "0c53"


def test_read_output_rejects_unknown_index():
    device = bt.Thermostat("AA:BB", bytes(32))
    with pytest.raises(ValueError):
        asyncio.run(device.read_output(7))
