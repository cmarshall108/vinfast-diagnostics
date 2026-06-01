import re

def main():
    with open("src/VF8Data.cpp", "r") as f:
        content = f.read()

    # Base DTC definitions
    sae_base = {
        "U0122": "Lost Communication With Vehicle Dynamics Control Module",
        "U0125": "Lost Communication With Multi-axis Acceleration Sensor Module",
        "U0146": "Lost Communication With Gateway A",
        "U0155": "Lost Communication With Instrument Panel Cluster (IPC) Control Module",
        "U0416": "Invalid Data Received From Vehicle Dynamics Control Module",
        "U0423": "Invalid Data Received From Instrument Panel Cluster (IPC) Control Module",
        "U3000": "Control Module (internal fault / self test)"
    }

    best_guess_base = {
        "U015C": "Lost communication with a camera / sensor module",
        "U0156": "Lost communication with display / information-center module",
        "U019E": "Lost communication with restraint / occupant module",
        "U01B0": "Lost communication on a private CAN sub-bus",
        "U020C": "Lost communication with battery-energy control module",
        "U045D": "Invalid data received from a chassis control module",
        "U0477": "Invalid data received from a driver-assistance module",
        "U0923": "Invalid data received from interior / roof control module",
        "U1003": "Lost communication with body-control / gateway module",
        "U1004": "Lost communication with a networked control module",
        "U1101": "Power-supply (KL30/KL15) voltage monitoring fault",
        "U1108": "Lost communication with Airbag Control Module (ACM)",
        "U1111": "Lost communication with a radar / camera sensor",
        "U1114": "Lost communication with a radar / camera sensor",
        "U1115": "Lost communication with a networked control module",
        "U1120": "Lost communication with a networked control module",
        "U1123": "Lost communication with a networked control module",
        "U1126": "Lost communication with a networked control module",
        "U1129": "Lost communication with a driver-assistance sensor",
        "U1130": "Lost communication with front radar sensor",
        "U1131": "Lost communication with front corner radar (right)",
        "U1132": "Lost communication with front corner radar (left)",
        "U1133": "Lost communication with rear corner radar",
        "U1135": "Lost communication with a networked control module",
        "U1136": "Lost communication with a driver-assistance sensor",
        "U1137": "Lost communication with a networked control module",
        "U1138": "Lost communication with a networked control module",
        "U1139": "Lost communication with a networked control module",
        "U1140": "Lost communication with surround-view camera",
        "U1141": "Lost communication with surround-view camera",
        "U1142": "Lost communication with surround-view camera",
        "U1148": "Lost communication with a driver-assistance module",
        "U1165": "Lost communication with a driver-assistance sensor",
        "U1171": "Chassis CAN communication bus fault",
        "U1182": "Lost communication with a driver-assistance module",
        "U1187": "Lost communication with a driver-assistance module",
        "U1191": "Lost communication with a body / comfort module",
        "U1192": "Lost communication with a driver-assistance module",
        "U1193": "Lost communication with a driver-assistance module",
        "U1196": "Lost communication with a driver-assistance module",
        "U1243": "Lost communication / configuration with DC-DC peripheral",
        "U1255": "Vehicle configuration / coding mismatch",
        "U160E": "Lost communication with a multimedia peripheral",
        "U3003": "Battery / power-supply voltage out of range",
        "P058D": "Battery / charging-system voltage sensor fault",
        "P0A95": "High-voltage system / HV fuse fault",
        "P0ABF": "Hybrid/EV battery current-sensor circuit fault",
        "P1017": "Drive-motor / inverter torque monitoring fault",
        "P1033": "HV contactor / pre-charge fault",
        "P105D": "Powertrain internal control fault",
        "P106B": "Powertrain internal control fault",
        "P1129": "Powertrain torque-control performance fault",
        "P1137": "Drive-motor performance fault",
        "P1150": "High-voltage system performance fault",
        "P1151": "High-voltage system performance fault",
        "P1188": "Powertrain coolant / thermal-management fault",
        "P1240": "HV battery contactor / pre-charge fault",
        "P1241": "HV battery contactor / pre-charge fault",
        "P1800": "Battery-management internal / control fault",
        "P1834": "Battery isolation / HV interlock fault",
        "P18D0": "Battery cell / balancing fault",
        "C0594": "Electronic stability control performance fault",
        "C150C": "DC-DC converter output fault",
        "C1536": "DC-DC converter / chassis sensor fault",
        "C1537": "DC-DC converter / chassis sensor fault",
        "B1014": "Right reverse-lamp circuit fault",
        "B1015": "Left stop-lamp circuit fault",
        "B1016": "Right stop-lamp circuit fault",
        "B10B8": "Body-control output circuit fault",
        "B10EC": "Body-control module internal fault",
        "B160D": "Audio / amplifier output circuit fault",
        "B160E": "Audio / amplifier output circuit fault",
        "B161A": "Microphone / audio-input circuit fault",
        "B161B": "Microphone / audio-input circuit fault",
        "B1620": "Display / touchscreen interface fault",
        "B170E": "Climate-control actuator / sensor fault",
        "B1908": "Driver-assistance radar alignment / blockage",
        "B1931": "Driver-assistance radar / camera fault",
        "B1932": "Driver-assistance radar / camera fault",
        "B1933": "Driver-assistance radar / camera fault",
        "B1934": "Driver-assistance radar / camera fault",
        "B1935": "Driver-assistance radar / camera fault",
        "B1937": "Driver-assistance radar / camera fault",
        "B1939": "Driver-assistance radar / camera fault",
        "B1940": "Driver-assistance radar / camera fault",
        "B1941": "Driver-assistance radar / camera fault",
        "B1942": "Driver-assistance radar / camera fault",
        "B2000": "Gateway / anti-theft system fault",
        "B2001": "Gateway / anti-theft system fault"
    }

    failure_types = {
        0x00: "No sub-type information",
        0x01: "General electrical failure",
        0x02: "General signal failure",
        0x03: "Frequency modulation / pulse width modulation failure",
        0x04: "System internal failure",
        0x07: "Mechanical failure",
        0x08: "Signal bus / message failure",
        0x09: "Component failure",
        0x11: "Circuit short to ground",
        0x12: "Circuit short to battery",
        0x13: "Circuit open",
        0x14: "Circuit short to ground or open",
        0x15: "Circuit short to battery or open",
        0x16: "Circuit voltage below threshold",
        0x17: "Circuit voltage above threshold",
        0x18: "Circuit current below threshold",
        0x19: "Circuit current above threshold",
        0x1A: "Circuit resistance below threshold",
        0x1B: "Circuit resistance above threshold",
        0x1C: "Circuit voltage out of range",
        0x1D: "Circuit current out of range",
        0x21: "Signal amplitude below minimum",
        0x22: "Signal amplitude above maximum",
        0x29: "Signal invalid",
        0x2F: "Signal erratic",
        0x38: "Frequency / pulse width out of range",
        0x49: "Internal electronic failure",
        0x4A: "Incorrect component installed",
        0x54: "Missing calibration",
        0x55: "Not programmed",
        0x62: "Signal compare failure",
        0x71: "Actuator stuck",
        0x81: "Invalid serial data received",
        0x82: "Alive / sequence counter incorrect or not updated",
        0x83: "Value of signal protection calculation incorrect",
        0x86: "Signal invalid / signal protection calculation failure",
        0x87: "Missing message",
        0x88: "Bus off",
        0x89: "Signal invalid / invalid serial data",
        0x92: "Performance or incorrect operation",
        0x96: "Component internal failure",
        0xA2: "Voltage / temperature signal erratic"
    }

    # Find the kVF8ReferenceScan block
    scan_match = re.search(r"const std::vector<VF8RefSystem> kVF8ReferenceScan = \{(.*?)\n\s*\};", content, re.DOTALL)
    if not scan_match:
        print("Could not find kVF8ReferenceScan block!")
        return

    block = scan_match.group(1)

    # We will process each DTC entry individually
    dtc_pattern = r'\{\"([A-Z0-9]{7})\",\s*\"([A-Za-z0-9]+)\",\s*\"\"\}'
    matches = re.findall(dtc_pattern, block)
    print(f"Found {len(matches)} DTCs without a definition.")

    # Let's count and list unique FTBs we need to support
    needed_ftbs = set()
    for dtc, status in matches:
        ftb = int(dtc[5:7], 16)
        needed_ftbs.add(ftb)
    print("Unique FTB bytes found:", [hex(f) for f in sorted(list(needed_ftbs))])

    # Replace DTCs in the file
    def replacer(m):
        dtc = m.group(1)
        status = m.group(2)
        base = dtc[:5]
        ftb = int(dtc[5:7], 16)

        ftb_desc = failure_types.get(ftb, f"failure type 0x{ftb:02X}")
        desc = ""
        is_guess = False
        if base in sae_base:
            desc = f"{sae_base[base]} - {ftb_desc}"
        elif base in best_guess_base:
            desc = f"{best_guess_base[base]} - {ftb_desc} (best guess)"
            is_guess = True
        else:
            desc = f"Unknown fault base {base} - {ftb_desc}"

        return f'{{"{dtc}", "{status}", "{desc}"}}'

    new_block = re.sub(dtc_pattern, replacer, block)
    new_content = content.replace(block, new_block)

    # Let's see if we should also add missing failure_types to vf8FailureType in the same script
    # For now, let's write out the new code to VF8Data.cpp
    with open("src/VF8Data.cpp", "w") as f:
        f.write(new_content)

    print("Successfully populated all empty DTC definitions in src/VF8Data.cpp!")

if __name__ == "__main__":
    main()
