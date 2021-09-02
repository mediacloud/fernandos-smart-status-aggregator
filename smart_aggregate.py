#!/usr/bin/env python3

import argparse
import csv
import dataclasses
import json
import logging
import os
import pprint
import re
import sys
from typing import Dict, Any, List, Optional, Tuple

import fabric

logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO').upper())


@dataclasses.dataclass(frozen=True, order=True)
class SmartCtlDevice(object):
    # e.g. "/dev/sda" or "/dev/bus/0":
    name: str

    # e.g. "scsi" or "megaraid,1":
    type: str


@dataclasses.dataclass(frozen=True, order=True)
class SmartCtlDeviceReport(object):
    # Decoded JSON report (with "--json" flag)
    json: Dict[str, Any]

    # Plain text report (without "--json" flag) as the JSON report doesn't include everything for SCSI drives
    plain: str


@dataclasses.dataclass(frozen=True, order=True)
class DeviceWWN(object):
    naa: int
    oui: int
    id: int

    def device_id(self) -> str:
        return f"{self.naa:x} {self.oui:x} {self.id:x}"


# Sometimes names are duplicated, e.g. "Unsafe_Shutdown_Count", so we can't use just the attribute name
@dataclasses.dataclass(frozen=True, order=True)
class DeviceSMARTAttributeName(object):
    id: int
    name: str

    def name_plus_id(self) -> str:
        return f"{self.name} (ID: {self.id})"


@dataclasses.dataclass(frozen=True, order=True)
class DeviceSMARTAttributeValue(object):
    value: int
    worst: int
    threshold: int

    # Sometimes it's a string, e.g.:
    #
    #     175 Power_Loss_Cap_Test 0x0033 100 100 010 Pre-fail Always - 2459 (3 7354)
    #
    raw_value: str


@dataclasses.dataclass(frozen=True, order=True)
class DeviceReport(object):
    host: str
    smartctl_device: SmartCtlDevice
    device_model: str
    serial_number: str
    wwn: Optional[DeviceWWN]
    user_capacity_bytes: int
    logical_block_size: int

    # Unset for SCSI drives
    physical_block_size: Optional[int]

    # If None, it's a SSD
    rotation_rate: Optional[int]

    # Sometimes it's set, sometimes it isn't
    form_factor: Optional[str]

    # Unset for SCSI drives
    interface_speed: Optional[str]

    smart_status_passed: bool

    # Unset on SCSI drives
    last_extended_offline_smart_test_status: Optional[str]

    # Unset on non-SCSI drives:
    manufactured_year: Optional[float]
    lifetime_cycle_count: Optional[int]
    acc_start_stop_cycles: Optional[int]
    load_unload_count: Optional[int]
    load_unload_cycles: Optional[int]
    grown_defect_count: Optional[int]

    smart_attributes: Dict[DeviceSMARTAttributeName, DeviceSMARTAttributeValue]


def _smartctl_json(connection: fabric.connection.Connection) -> Dict[SmartCtlDevice, SmartCtlDeviceReport]:
    logging.debug(f"Scanning disks on host {connection.original_host}...")

    smartctl_scan = json.loads(connection.sudo('smartctl --json --scan', hide=True).stdout.strip())
    devices = [SmartCtlDevice(name=device['name'], type=device['type']) for device in smartctl_scan['devices']]

    reports: Dict[SmartCtlDevice, SmartCtlDeviceReport] = dict()
    for device in devices:
        logging.debug(f"Reading report on host {connection.original_host}, device {device.name}, type {device.type}...")

        smartctl_json_report = connection.sudo(
            f'smartctl --json -a {device.name} -d {device.type}',
            hide=True,
            # Silently ignore disks that can't report SMART status, e.g. RAID 1's that make up root volume
            warn=True,
        )
        smartctl_plain_report = connection.sudo(
            f'smartctl -a {device.name} -d {device.type}',
            hide=True,
            # Silently ignore disks that can't report SMART status, e.g. RAID 1's that make up root volume
            warn=True,
        )

        reports[device] = SmartCtlDeviceReport(
            json=json.loads(smartctl_json_report.stdout.strip()),
            plain=smartctl_plain_report.stdout.strip(),
        )

    return reports


def smart_flattened_reports(hosts: List[str]) -> List[DeviceReport]:
    all_host_reports: Dict[str, Dict[SmartCtlDevice, SmartCtlDeviceReport]] = {}

    # FIXME ThreadingGroup doesn't spawn no threads
    for connection in fabric.ThreadingGroup(*hosts):
        all_host_reports[connection.original_host] = _smartctl_json(connection)

    flattened_reports: List[DeviceReport] = []

    pp = pprint.PrettyPrinter(indent=4)

    for host, reports in sorted(all_host_reports.items()):

        # Specify types to PyCharm
        host: str = host
        reports: Dict[SmartCtlDevice, SmartCtlDeviceReport] = reports

        # Some servers have some disks unconfigured, so they're detected twice by "smartctl --scan":
        #
        #     # smartctl --scan
        #     /dev/sda -d scsi # /dev/sda, SCSI device                              <--- serial "0123456789ABCDE"
        #     /dev/sdb -d scsi # /dev/sdb, SCSI device
        #     /dev/bus/0 -d megaraid,0 # /dev/bus/0 [megaraid_disk_00], SCSI device
        #     /dev/bus/0 -d megaraid,1 # /dev/bus/0 [megaraid_disk_01], SCSI device
        #     /dev/bus/0 -d megaraid,2 # /dev/bus/0 [megaraid_disk_02], SCSI device <--- serial "0123456789ABCDE"
        #
        # and for whatever reason smartctl can't run the "Extended Offline" test on the "/dev/sdX -d scsi" disk, so we
        # deduplicate these here leaving only the "/dev/bus/X -d megaraid,Y" entry.
        reports_by_serial_number: Dict[str, Tuple[SmartCtlDevice, SmartCtlDeviceReport]] = dict()
        # noinspection PyTypeChecker
        for disk, report in sorted(reports.items()):

            # Make PyCharm smart again
            disk: SmartCtlDevice = disk
            report: SmartCtlDeviceReport = report

            serial_number = report.json['serial_number'].strip().lower()
            if serial_number in reports_by_serial_number:
                existing_disk, _ = reports_by_serial_number[serial_number]
                logging.debug(f"Existing duplicate disk: {existing_disk}")

                if existing_disk.type.startswith('megaraid'):
                    assert not disk.type.startswith('megaraid'), f"Two MegaRAID disks on host {host} with same serial."

                    # Existing disk MegaRAID, new disk is not MegaRAID, so leave the old one
                    overwrite_disk = False
                else:
                    assert disk.type.startswith('megaraid'), f"Two non-MegaRAID disks on host {host} with same serial."

                    # Existing disk is not MegaRAID, new disk is MegaRAID, so overwrite with the new one
                    overwrite_disk = True
            else:
                # First time we're seeing this disk
                overwrite_disk = True

            if overwrite_disk:
                logging.debug(f"Under serial number {serial_number} storing disk {disk}")
                reports_by_serial_number[serial_number] = (disk, report,)

        logging.debug(f"Deduplicated disks:\n{pp.pformat(reports_by_serial_number)}")

        reports: Dict[SmartCtlDevice, SmartCtlDeviceReport] = dict()
        for serial_number, disk_and_reports in reports_by_serial_number.items():
            disk, report = disk_and_reports
            reports[disk] = report

        # noinspection PyTypeChecker
        for disk, report in sorted(reports.items()):

            # Make PyCharm smart again
            disk: SmartCtlDevice = disk
            report: SmartCtlDeviceReport = report

            # Skip RAID controllers themselves
            if report.json.get('vendor', None) == 'DELL' and report.json.get('product', '').startswith('PERC'):
                continue

            logging.debug((
                f"Host: {host}, disk: {disk}, "
                f"JSON report:\n{pp.pformat(report.json)}\n"
                f"Plain report: {report.plain}"
            ))

            ata_smart_self_test_log = report.json.get('ata_smart_self_test_log', None)
            if ata_smart_self_test_log:

                last_self_test_status = None
                for self_test in ata_smart_self_test_log['standard']['table']:
                    if self_test['type']['string'] == 'Extended offline':
                        last_self_test_status = self_test['status']['string']

                assert last_self_test_status, f"'Extended offline' test not found on host {host}, disk {disk}."
            else:
                last_self_test_status = None

            manufactured_year = re.search(r'Manufactured in week \d+? of year (\d+?)\n', report.plain)
            manufactured_year = int(manufactured_year.group(1)) if manufactured_year else None

            lifetime_cycle_count = re.search(r'Specified cycle count over device lifetime:\s+?(\d+?)\n', report.plain)
            lifetime_cycle_count = int(lifetime_cycle_count.group(1)) if lifetime_cycle_count else None

            acc_start_stop_cycles = re.search(r'Accumulated start-stop cycles:\s+?(\d+?)\n', report.plain)
            acc_start_stop_cycles = int(acc_start_stop_cycles.group(1)) if acc_start_stop_cycles else None

            load_unload_count = re.search(r'Specified load-unload count over device lifetime:\s+?(\d+?)\n',
                                          report.plain)
            load_unload_count = int(load_unload_count.group(1)) if load_unload_count else None

            load_unload_cycles = re.search(r'Accumulated load-unload cycles:\s+?(\d+?)\n', report.plain)
            load_unload_cycles = int(load_unload_cycles.group(1)) if load_unload_cycles else None

            grown_defect_count = re.search(r'Elements in grown defect list:\s+?(\d+?)\n', report.plain)
            grown_defect_count = int(grown_defect_count.group(1)) if grown_defect_count else None

            assert last_self_test_status is not None or grown_defect_count is not None, (
                f"At least last self-check status or the grown defect count should be set for host {host}, disk {disk}."
            )

            rotation_rate = report.json['rotation_rate'] if report.json['rotation_rate'] else None

            disk_attributes: Dict[DeviceSMARTAttributeName, DeviceSMARTAttributeValue] = dict()

            ata_smart_attributes = report.json.get('ata_smart_attributes', None)

            # HDDs don't report SMART attributes
            if ata_smart_attributes:
                for disk_attribute in sorted(report.json['ata_smart_attributes']['table'], key=lambda row: row['name']):
                    attribute_name = DeviceSMARTAttributeName(id=disk_attribute['id'], name=disk_attribute['name'])
                    assert attribute_name not in disk_attributes, (
                        f"Duplicate attribute '{attribute_name}' for host {host}, disk {disk}."
                    )

                    disk_attributes[attribute_name] = DeviceSMARTAttributeValue(
                        value=disk_attribute['value'],
                        worst=disk_attribute['worst'],
                        threshold=disk_attribute['thresh'],
                        raw_value=disk_attribute['raw']['string'],
                    )
            else:
                assert rotation_rate, f"Disk {disk} on host {disk} is SSD but doesn't have SMART attributes."

            if 'wwn' in report.json:
                wwn = DeviceWWN(
                    naa=report.json['wwn']['naa'],
                    oui=report.json['wwn']['oui'],
                    id=report.json['wwn']['id'],
                )
            else:
                wwn = None

            if 'interface_speed' in report.json:
                interface_speed = report.json['interface_speed']['current']['string']
            else:
                interface_speed = None

            if 'form_factor' in report.json:
                form_factor = report.json['form_factor']['name']
            else:
                form_factor = None

            flattened_reports.append(DeviceReport(
                host=host,
                smartctl_device=disk,
                device_model=report.json['model_name'],
                serial_number=report.json['serial_number'],
                wwn=wwn,
                user_capacity_bytes=report.json['user_capacity']['bytes'],
                logical_block_size=report.json['logical_block_size'],
                physical_block_size=report.json.get('physical_block_size', None),
                rotation_rate=report.json['rotation_rate'] if report.json['rotation_rate'] else None,
                form_factor=form_factor,
                interface_speed=interface_speed,
                smart_status_passed=report.json['smart_status']['passed'],
                manufactured_year=manufactured_year,
                lifetime_cycle_count=lifetime_cycle_count,
                acc_start_stop_cycles=acc_start_stop_cycles,
                load_unload_count=load_unload_count,
                load_unload_cycles=load_unload_cycles,
                grown_defect_count=grown_defect_count,
                last_extended_offline_smart_test_status=last_self_test_status,
                smart_attributes=disk_attributes,
            ))

    return flattened_reports


def smart_aggregate():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', nargs='+', required=True,
                        help='One or more hosts to query for SMART status')

    args = parser.parse_args()

    flattened_reports = smart_flattened_reports(hosts=args.host)

    unique_smart_attribute_names = set()
    for report in flattened_reports:
        for attribute_name in report.smart_attributes.keys():
            unique_smart_attribute_names.add(attribute_name)
    # noinspection PyTypeChecker
    unique_smart_attribute_names = sorted(list(unique_smart_attribute_names))

    header_row = [
        'Host',
        '`smartctl` Disk Name',
        '`smartctl` Disk Type',
        'Device Model',
        'Serial Number',
        'LU WWN Device Id',
        'User Capacity',
        'Logical Block Size',
        'Physical Block Size',
        'Rotation Rate',
        'Form Factor',
        'Interface Speed',
        'SMART Status Passed',
        'Year of Manufacture',
        'Specified cycle count over device lifetime',
        'Accumulated start-stop cycles',
        'Specified load-unload count over device lifetime',
        'Accumulated load-unload cycles',
        'Elements in grown defect list',
        'Last SMART "Extended offline" (`-t long`) Test Status',
    ]
    for attribute_name in unique_smart_attribute_names:
        header_row.append(f"{attribute_name.name_plus_id()}: value")
        header_row.append(f"{attribute_name.name_plus_id()}: worst")
        header_row.append(f"{attribute_name.name_plus_id()}: threshold")
        header_row.append(f"{attribute_name.name_plus_id()}: raw value")

    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerow(header_row)

    for report in flattened_reports:
        row = [
            report.host,
            report.smartctl_device.name,
            report.smartctl_device.type,
            report.device_model,
            report.serial_number,
            report.wwn.device_id() if report.wwn else None,
            report.user_capacity_bytes,
            report.logical_block_size,
            report.physical_block_size,
            report.rotation_rate if report.rotation_rate else "Solid State Drive",
            report.form_factor,
            report.interface_speed,
            report.smart_status_passed,
            report.manufactured_year,
            report.lifetime_cycle_count,
            report.acc_start_stop_cycles,
            report.load_unload_count,
            report.load_unload_cycles,
            report.grown_defect_count,
            report.last_extended_offline_smart_test_status,
        ]
        for attribute_name in unique_smart_attribute_names:
            attribute = report.smart_attributes.get(attribute_name, None)
            if attribute:
                row.append(attribute.value)
                row.append(attribute.worst)
                row.append(attribute.threshold)
                row.append(attribute.raw_value)
            else:
                # A bit silly to do it this way
                row.append(None)
                row.append(None)
                row.append(None)
                row.append(None)

        assert len(header_row) == len(row), (
            f"Header row ({len(header_row)}) doesn't have the same amount of items as data row ({len(row)}."
        )

        csv_writer.writerow(row)

    sys.stdout.flush()


if __name__ == '__main__':
    smart_aggregate()
