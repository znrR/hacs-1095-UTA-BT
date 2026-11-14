# Effective setpoint readback

Version 0.1.2 adds a read after an accepted preset change. The existing mode writes remain unchanged. No temperature value is written by the refresh.

## APK evidence

The supplied free@home Next ARM64 binary contains:

- `TelegramFactory::getDataPointValue` at `0x509e22c`: for `isInput=false`, selects device property `0xDF` and datapoint service `0x01`, appends the one-based channel, then the output index and finalizes lengths.
- `TelegramFactory::functionPropertyCommand` at `0x509e4c8`: constructs the function-property command envelope (`APCI 0x02C7`).
- `DatapointReader::start` at `0x4faddb8`: calls that factory method and registers a matching response callback.
- `DatapointReader::handleDPValue` at `0x4fadb20`: checks the returned datapoint index, then decodes the following value using the datapoint type. `XmlJobBase::setDataPointValue` at `0x50b1930` calls `IncomingTelegram::readValue`.

For the supported channel 1 / function CF mapping, output 2 is effective setpoint (pairing `0x0033`, DPT 9.001).

## Request

The uncompressed factory frame for source `FFF0`, destination `0201`, channel 1, output 2 is:

```text
11 00 04 00 FF F0 02 01 09 02 C7 00 DF 00 01 03 00 01 02
```

It is sent through the existing authenticated encrypted transport with the per-telegram prefix `03 02 00 00`. Transport/cipher counters continue across reads and writes.

Only a reply matching property `DF`, service `01`, channel 1, output 2, and the configured device source can satisfy the read. The value after the echoed index must contain exactly two bytes and is decoded as KNX float16. A rejected/malformed reply does not change the accepted preset or cause a command replay. A transport failure requires a new authenticated session.

The coordinator waits 300 ms after the mode acknowledgements before reading to allow the control cycle to apply the mode. The old effective setpoint is cleared until a fresh read/report arrives; a fresh report received during the mode writes is retained.

## Validation status

The frame construction and reply handling are covered by simulated encrypted sessions, including repeated mode changes, a different effective Eco target, mismatched acknowledgements, malformed/rejected reads, and timeout handling. The new read transaction has **not yet been validated on the physical thermostat**. The request follows the reconstructed app path; the expected reply layout follows the app's reader and existing function-property replies. Synthetic responses are test fixtures, not recorded read transactions.

# Output datapoints, on/off and group addresses

Checked on a second 1095 UTA-BT installation by reading outputs while changing setpoint, Eco and on/off at the device.

## Outputs of channel 1

`output_read(index)` builds the same frame as the setpoint read with another output index. Indices 1–11 answer; 12 and above time out and leave the session unusable.

| Output | Pairing ID (ABB local API) | Meaning | Payload |
|---|---|---|---|
| 1 | 0x0030 | actuating value heating | 1 byte, 0–255 = 0–100 % |
| 2 | 0x0033 | effective setpoint (Eco setpoint while Eco is active, 7 °C when off) | KNX float16 |
| 3 | 0x0034 | relative setpoint (user offset) | KNX float16 |
| 4 | 0x0038 | controller on (1) / protection mode (0) | 1 byte |
| 5 | 0x0036 | status indication | 1 byte bitmask |
| 9 | 0x0130 | measured room temperature | KNX float16 |

Outputs 6, 7, 8, 10 and 11 answer (`05`, 4 × `00`, `00`, `00`, `00000000ffffffff`) but never changed during the tests and are not decoded.

Status bits (ABB local API, matches observed `21` comfort/heating, `61` comfort/no demand, `64` eco/no demand): `01` comfort, `02` standby, `04` eco, `08` building protection, `10` dew alarm, `20` heating (set) / cooling (unset), `40` no heating or cooling, `80` frost alarm.

## On/off

Input 6 is the controller on/off request (pairing 0x0042); `set_eco` already writes it as 1. Writing 0 switched the controller to protection mode (output 4 = 0, setpoint 7.0 °C, actuating value 0); writing 1 restored comfort mode and the previous setpoint. `Thermostat.set_power()` wraps this.

## Group addresses are per installation

The pushed group telegrams carry the same datapoints, but the addresses differ between installations. In the second installation: measured temperature `B94B` (about once per second), setpoint `4D57`, relative setpoint `AE28`, actuating value `E7EF`, status `AFC6`. The original `704B / 6467 / 3F71 / 8FFD` therefore only work for the first installation. `Thermostat(groups=...)` takes a per-installation map, and telegrams for unmapped addresses are emitted as `group_report` events. Reading the outputs needs no address map.
